export default () => ({
    port: parseInt(process.env.PORT, 10) || 3000,
    database: {
        host: process.env.DATABASE_HOST,
        port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
    },
    MONGODB_URI: process.env.MONGODB_URI,
    PORT: 3000,
    JWT_SECRET: 'SECRETKEY',
    GOOGLE_CLIENT_ID: 'OAuth Credentials',
    OTP_SECRET: '0123456789',
    MAIL_USERNAME: 'apikey',
    MAIL_PASSWORD: 'Mailer Password',
    MAIL_EMAIL: "Email address of developer who have used OAuth to login",
});
