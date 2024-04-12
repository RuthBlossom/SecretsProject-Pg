
# Secrets Sharing Web Application

This is a web application for sharing secrets anonymously. Users can register, log in, and submit their secrets, which are stored securely in a PostgreSQL database. The project is built using Node.js and Express.js for the backend, with Passport.js for user authentication and bcrypt for password hashing.

## Features

- User registration and login
- Anonymous secret submission
- Google authentication option
- Session management
- Secure password storage using bcrypt
- PostgreSQL database integration

## Prerequisites

Before running this project, make sure you have the following installed:

- Node.js
- npm (Node Package Manager)
- PostgreSQL

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   ```

2. Navigate to the project directory:

   ```bash
   cd secrets-web-app
   ```

3. Install dependencies:

   ```bash
   npm install
   ```

4. Set up environment variables:
   
   Create a `.env` file in the root directory and add the following variables:

   ```
   SESSION_SECRET=your_session_secret_key
   PG_USER=your_postgres_username
   PG_HOST=your_postgres_host
   PG_DATABASE=your_postgres_database
   PG_PASSWORD=your_postgres_password
   PG_PORT=your_postgres_port
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   ```

5. Start the server:

   ```bash
   npm start
   ```

## Usage

- Open your web browser and navigate to `http://localhost:3000`.
- Register for a new account or log in with an existing one.
- Share your secrets anonymously or view secrets submitted by others.
