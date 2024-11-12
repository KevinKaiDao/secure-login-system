const express = require("express");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})

// AWS COGNITO (DAY 1-2)
const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");


AWS.config.update({
    region: process.env.AWS_REGION,
});

const cognito = new AWS.CognitoIdentityServiceProvider();

app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    try{
        // Generate a unique user ID
        const userID = uuidv4();

        // Has the password
        const hasedPassword = await bcrypt.hash(password, 10);

        // Cognito sign-up params
        const params = {
            ClientId: process.env.AWS_CLIENT_ID,
            Username: username,
            Password: password,
            UserAttributes: [
                {
                    Name: "email",
                    Value: username, // Email as username
                },
            ],
        };
    
        // Register user with Cognito
        await cognito.signUp(params).promise();

        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Error registering user:", err);
        res.status(500).json({error: "Failed to register user"});
    }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        // Authenticate user with Cognito
        const params = {
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: process.env.AWS_CLIENT_ID,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
            },
        };

        const authResult = await cognito.initiateAuth(params).promise();

        // Generate JWT token
        const token = jwt.sign(
            { username: username },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ token });
    } catch (err) {
        console.error("Error logging in:", err);
        res.status(401).json({ error: "Invalid credentials" });
    }
});

function authenticate(req, res, next) {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
}

app.get("/profile", authenticate, (req, res) => {
    res.json({
        message: "This is a protected route",
        user: req.user,
    })
})