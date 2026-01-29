# Foodle Backend

Node.js Express server for the Foodle food recommendation application.

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment variables:**
   - Copy `.env.example` to `.env`
   - Fill in your API keys and secrets
   - **NEVER commit `.env` to GitHub**

3. **Start the server:**
   ```bash
   npm start
   ```

The server will run on `http://localhost:5000`

## Environment Variables

Required variables in `.env`:
- `MONGODB_URI` - MongoDB Atlas connection string
- `JWT_SECRET` - Secret key for JWT tokens
- `SESSION_SECRET` - Secret key for session management
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret
- `OPENAI_API_KEY` - OpenAI API key for recommendations
- `GOOGLE_PLACES_API_KEY` - Google Places API key
- `FRONTEND_URL` - Frontend application URL (for CORS)

## Important Security Notes

⚠️ **NEVER** commit API keys or secrets to GitHub:
- All sensitive data must be in `.env`
- `.env` is protected by `.gitignore`
- Environment variables are injected at runtime
- Use different secrets for production

## API Endpoints

- `POST /api/recommend-restaurant` - Get restaurant recommendations
- `POST /api/message` - Send chat messages
- `POST /api/nearby-restaurants` - Find nearby restaurants
- `GET/POST /api/user/profile` - User profile management
- `POST /auth/google` - Google OAuth authentication

## Database

Connected to MongoDB Atlas for user data, preferences, and history.

## Deployment

Deploy to Render.com:
1. Set all environment variables in Render dashboard
2. Ensure `.env` is in `.gitignore`
3. Push to GitHub
4. Render will auto-deploy on push

