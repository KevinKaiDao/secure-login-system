# Secure Login System with AWS Cognito and JWT Authentication

A secure login system built with **AWS Cognito**, **Express.js**, and **JWT Authentication**. This project includes user registration, login, token-based session management, and a refresh token mechanism, along with a protected profile endpoint.

## Features

- User registration with AWS Cognito
- Secure login using username and password
- JSON Web Token (JWT) authentication for session management
- Token refresh endpoint for renewing expired tokens
- Protected profile endpoint to retrieve user-specific data
- Comprehensive API documentation for easy integration

---

## Technologies Used

- **AWS Cognito**: For user management and authentication
- **Express.js**: Backend framework for API development
- **jsonwebtoken**: For generating and verifying JWTs
- **dotenv**: For managing environment variables

---

## Prerequisites

1. **AWS Cognito Setup**:
   - Create a user pool in AWS Cognito.
   - Configure an app client and note down the `ClientId`.
   - Add necessary credentials to the `.env` file.

2. **Environment Variables**:
   Add the following to your `.env` file:
   ```env
   AWS_REGION=your-aws-region
   AWS_USER_POOL_ID=your-user-pool-id
   AWS_CLIENT_ID=your-app-client-id
   JWT_SECRET=your-very-secure-secret
