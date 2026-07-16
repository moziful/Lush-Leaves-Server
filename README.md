# 🍃 Lush Leaves (Backend Server)

Express.js REST API backend server managing database persistence, user roles, security, session tokens, and plant listings for the **Lush Leaves** e-commerce app. 

## 🛡️ Key Features

*   **Google OAuth Verification**: Secure endpoint `POST /api/auth/google` verifying JWT idTokens using Google's official `OAuth2Client` and handling automatic MongoDB user registration.
*   **Security & JWT Validation**: Custom middlewares validating route permissions. Protects sensitive write configurations and items administration from unauthorized users.
*   **Stripe Integration**: Secure backend checkout sessions generation and order placement verification.
*   **MongoDB Persistence**: Fully typed model queries and listings management with fallback mock utilities to ensure zero runtime crashes.
*   **Vercel Serverless Ready**: Packaged routing structures (`vercel.json`) allowing deployment as Serverless functions.

---

## 🛠️ Technology Stack

*   **Engine**: Node.js & Express.js
*   **Language**: TypeScript (compiled with `tsc`)
*   **Database**: MongoDB Driver (Native)
*   **Authentication**: `google-auth-library`, `jsonwebtoken`
*   **Deployments**: Vercel Serverless Configurations

---

## ⚙️ Installation & Setup

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/moziful/Lush-Leaves-Server.git
    cd Lush-Leaves-Server
    ```

2.  **Install Dependencies**:
    ```bash
    npm install
    ```

3.  **Environment Variables Setup**:
    Create a `.env` file in the root directory:
    ```env
    PORT=5000
    MONGODB_URI=your_mongodb_uri
    JWT_SECRET=your_jwt_secret_key
    STRIPE_SECRET_KEY=your_stripe_secret_key
    NEXT_PUBLIC_GOOGLE_CLIENT_ID=your_google_oauth_client_id
    ```

4.  **Run Development Server**:
    ```bash
    npm run dev
    ```
    The server will start on `http://localhost:5000`.

5.  **Build TypeScript Output**:
    ```bash
    npm run build
    ```
