import express from "express"
import mongoose from "mongoose"
import authRoute from "./routes/auth_route.js"
import dotenv from "dotenv"

const app = express()

dotenv.config({ path: './conn.env' });

mongoose.connect(process.env.CONN_STR)

const db = mongoose.connection

db.on('error', (error) => console.log(error))
db.once('open', () => console.log('database connected'))

app.use(express.json())

app.use('/', authRoute)

app.listen(3000, () => console.log('Server started on port 3000'))