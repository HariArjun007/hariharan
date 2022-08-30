const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const Jwt = require("jsonwebtoken");
const {promisify} = require("util");
const db=mysql.createConnection(
    {
        host:process.env.DATABASE_HOST,
        user:process.env.DATABASE_USER,
        password:process.env.DATABASE_PASSWORD,
        database:process.env.DATABASE,
    }
);
exports.login= async(req,res) => {
    try {
        const {email,password } = req.body;
        if (!email || !password){
            return res.status(400).render("index",
            {msg:"please enter your email id and password",msg_type:"error"}
            )
        }
        db.query(
            "select * from log where email=?",
            [email],
            async (error,result) => {
                console.log(result);
                if (result.length<=0){
                    return res.status(401).render("index",{
                        msg:"Email or password incorrect",
                        msg_type:"error"
                    });
                }else{
                    if(!(await bcrypt.compare(password,result[0].PASS))){
                        return res.status(401).render("index",{
                            msg:"Email or password incorrect",
                            msg_type:"error"
                    });
                }else{
                    const id =result[0].ID;
                    const token=Jwt.sign({id:id},process.env.JWT_SECRET,{
                    expiresIn:process.env.JWT_EXPIRES_IN,
                    });
                    console.log("The Token is" + token);
                    const cookieOptions ={
                        expires:new Date(
                            Date.now() +
                             process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                        ),
                        httpOnly: true,
                        };
                        res.cookie("hero",token,cookieOptions);
                        res.status(200).redirect("/home");
                    };
                }
            }
        );
        }catch (error) {
        console.log(error);
    }

};
exports.register=(req,res) => {
    console.log(req.body);
   // res.send("FORM SUBMITTED")
   const {name,email,password,conform_password} = req.body;
   db.query('select email from login where email=?',[email],async (error,result) => {
    if (error){
        console.log(error);
    }
    
    if(result.length>0){
        return res.render("register",{msg:"Email id already taken",msg_type:"error"});
    }

    else if (password!==conform_password){ 
    return res.render("register", {msg: "password do not match",msg_type:"error"});
    };
    let hashedpassword = await bcrypt.hash(password,8);

    db.query("insert into log set?",
    {name: name,email:email,pass:hashedpassword},
    (error,result)=> {
        if (error){
            console.log(error);
        } else{
            console.log(result);
            return res.render("register", {msg: "User registration successfull",msg_type:"good"});
        }

        }
    );

    }
    );
};


exports.isLoggedIn = async (req,res,next) => {
   // req.name = "Check login....";
    
 // console.log(req.cookies);
 // next();
   if (req.cookies.hero){

    try{
        const decode= await promisify(Jwt.verify)(
            req.cookies.hero,
            process.env.JWT_SECRET
        );
        // console.log(decoded);
        db.query("select * from log where id=?",[decode.id],(err,results) => {
           // console.log(results);
           if (!results){
            return next();
           }
           req.user = results[0];
           return next();
        });
     }catch (error){
        console.log(error);
        return next();
     }
    
   }else{
    next();
   };


} ; 

exports.logout = async (req,res) => {
    res.cookie("hero","logout",{
        expires:new Date(Date.now()+ 2* 1000),
        httpOnly:true,
    });
    res.status(200).redirect("/");
};

   




