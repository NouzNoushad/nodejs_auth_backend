import express from "express"
import { signup, signIn, logout } from "../controllers/auth_controller.js"
import { verifyToken } from "../middlewares/verification.js"

const router = express.Router()

router.post('/signup', signup)
router.post('/sign_in', signIn)
router.get('/logout',verifyToken, logout)

export default router