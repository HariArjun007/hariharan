const express=require("express");
const userController=require("../controllers/users.js");
const router=express.Router();

router.post("/register",userController.register);
router.post("/login",userController.login);
router.get("/logout",userController.logout);
module.exports=router;
