import express from "express"
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";


env.config();
const saltRounds = 10;
const app = express();
const port = 3000;



// USING
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

app.use(session({
  secret:process.env.TOP_SECRET,
  resave:false,
  saveUninitialized:true,
  cookie:{
    maxAge:1000*60*60*24
  }
}));
app.use(passport.initialize());
app.use(passport.session());


const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT
});

db.connect();


// GET THE CONGRATS
app.get("/congrats",(req,res)=>{
  if( req.isAuthenticated()){
    res.render("congrats.ejs");
  }
  else{
    console.log("Here\n");
    res.redirect("/login");
  }

})

// GETTING THE HOME PAGE, LOGIN PAGE AND REGISTER PAGES
app.get("/",(req,res)=>{
  res.render("home.ejs");
});

app.get("/login",(req,res)=>{
  res.render("login.ejs");
})

app.get("/register",(req,res)=>{
  res.render("register.ejs");
})

// POST LOGIN 

app.post("/login",passport.authenticate("local",{
  successRedirect:"/congrats",
  failureRedirect:"/login"
}));

// POST REGISTER

app.post("/register",async(req,res)=>{

  const email = req.body.username;
  const password = req.body.password;

  try{
  // CHECK IF USER ALREADY REGISTERED
  const response = await db.query("select * from users where email = ($1)",[email]);

  if( response.rows.length > 0 ){
    // USER IS ALREADY REGISTED
    console.log("User already exists.");
    res.redirect("/login");
  }

  else{
    // USER IS NOT REGISTERED, SO ENCRYPT AND REGISTER HIM
    bcrypt.hash(password,saltRounds,async(error,hash)=>{
      const response = await db.query("insert into users(email,password) values($1,$2) returning *",[email,hash]);
      const user = response.rows[0];
      req.login(user,(err)=>{
        if( err ){
          console.log(err);
        }
        else{
          res.redirect("/congrats");
        }
      })
    })
  }
}
catch(error){
  console.log("Error registering user.");
}
});



passport.use(

  new Strategy( async function verify(username,password,cb){
    try{

      const response = await db.query("select * from users where email=($1)",[username]);
    
      if( response.rows.length > 0 ){
        
        // LOGIN IS PRESENT, CHECK PWD
        const user = response.rows[0];
        const cor_password = user.password;
        
        bcrypt.compare(password,cor_password, (error,valid)=>{
          if( error ){
            console.log("Error comparing passwords");
            return cb(error);
          }
          else{
            if( valid ){
              console.log("Valid.");
              return cb(null,user);
            }
            else{
              console.log("Not valid");
              return cb(null,false);
            }
          }
        });
      }
      // EMAIL IS NOT PRESENT, SO USER HAS TO REGISTER
      else{
        console.log("User not found");
        return cb("User not found.");
      }
    }
    catch(error){
      console.log("Error");
    }
    

  })

);

passport.serializeUser( (user,cb) =>{
  cb(null,user);
});

passport.deserializeUser( (user,cb) =>{
  cb(null,user);
});


app.listen(port,()=>{
  console.log("Listening to port " + port);
});




