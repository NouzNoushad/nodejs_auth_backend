import jsonwebtoken from "jsonwebtoken"
import { tokenList } from "../controllers/auth_controller.js"

export const verifyToken = (req, res, next) => {
	try {
		const token = req.headers.authorization.split(' ')[1]
		const decode = jsonwebtoken.verify(token, process.env.SECRET_KEY)
		if (!tokenList.has(token)) {
			req.userId = decode.id
			req.name = decode.name
			next()
		}else {
			res.status(401).json({message: 'You are not authorized'})
		}
	} catch (error) {
		res.status(401).json({message: 'You are not authorized', error: error})
	}
}