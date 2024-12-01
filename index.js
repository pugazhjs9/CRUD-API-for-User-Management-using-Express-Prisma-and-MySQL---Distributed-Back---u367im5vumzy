const express = require('express');
const dotenv = require('dotenv'); 
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const {prisma} = require("./db/config")
dotenv.config(); 

const app = express();

const JWT_SECRET = "68d97a7b7965450091cd86a139a66caaca857c05511860b11b0064e388ba105328de791c8336dd7561f52ea7f2fa64f2d09810cfea12978b571cdceab05270b"
const BCRYPT_SALT = 10

app.use(express.json());

app.post("/api/auth/signup",async (req,res)=>{
  const {name,email,password} = req.body;
  if (!email && !password){
    return res.status(400).json({"error":"Email and Password are required"})
  }if(!email){
    return res.status(400).json({"error":"Email is required"})
  }if (!password){
    return res.status(400).json({error:"Password is required"})
  }
  try{
    const existing = await prisma.user.findUnique({where:{email}})
    if (existing){
      return res.status(400).json({error:"Email already in use"})
    }
    const hashedpass = await bcrypt.hash(password,BCRYPT_SALT);
    const newuser = await prisma.user.create({
      data:{name,email,password:hashedpass}
    });
    return res.status(201).json({
      "message":"User created successfully",
      "userId":newuser.id
    })
  }catch(err){
    console.log(err)
    return res.status(500).json({error:"Internal Server Error"})
  }
});

app.post("/api/auth/login",async (req,res)=>{
  const {email,password} = req.body;
  if (!email || !password){
    return res.status(400).json({error:"Email and Password are required"})
  }
  try{
    const user = await prisma.user.findUnique({where : {email}})
    if (!user){
      return res.status(404).json({error:"User not found"})
    }
    const isvalidPasword = await bcrypt.compare(password,user.password)
    if (!isvalidPasword){
      return res.status(401).json({"error":"Invalid Credential"})
    }
    const token = await jwt.sign({userId:user.id,email:user.email},JWT_SECRET,{
      "expiresIn":"1hr",
    })
    return res.status(200).json({
      userdata:{
        "id":user.id,"name":user.name,"email":user.email
      },"accesstoken":token,
    })
  }catch(err){
    console.log(err)
    return res.status(500).json({error:"Internal Server Error"})
  }
})

const PORT = process.env.PORT || 3000;  
app.listen(PORT, () => {
  console.log(`Backend server is running at http://localhost:${PORT}`);
});

module.exports=  app;