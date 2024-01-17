import mongoose from "mongoose"
import bcrypt from "bcrypt"
import jsonwebtoken from "jsonwebtoken"
import authSchema from "../models/auth_model.js"

const db = mongoose.connection

export const signup = async (req, res) => {
	try {
		const { name, email, password } = req.body
		bcrypt.hash(password, 10).then(async (password) => {
			const authModel = authSchema({
				name,
				email,
				password
			})
			const auth = await authModel.save()
			res.status(201).json({message: "Account has created", data: {name: auth.name, email: auth.email, password: auth.password}})
		})
	} catch (error) {
		res.status(500).json({message: 'Error while signup', error: error})
	}
}

export const signIn = async (req, res) => {
	try {
		const user = await db.collection('auths').findOne({ email: req.body.email })
		if (user) {
			bcrypt.compare(req.body.password, user.password).then((status) => {
				if (status) {
					jsonwebtoken.sign({ id: user._id, name: user.name }, process.env.SECRET_KEY, { expiresIn: 60 * 60 * 24 * 30 }, (error, token) => {
						if (token) {
							res.status(200).json({message: 'successfully logged in', token: token})
						} else {
							res.status(404).json({message: 'something went wrong', error: error})
						}
					})
				} else {
					res.status(404).json({message: 'password not matching'})
				}
			})
		} else {
			res.status(404).json({message: 'user not found'})
		}
	} catch (error) {
		res.status(500).json({message: 'Error while sign in', error: error})
	}
}

export const tokenList = new Set()

export const logout = (req, res) => {
	try {
		const token = req.headers.authorization.split(' ')[1]
		tokenList.add(token)
		jsonwebtoken.verify(token, process.env.SECRET_KEY, {
			ignoreExpiration: true
		})
		res.status(200).json({message: 'successfully logged out'})
	}catch (error) {
		res.status(500).json({message: 'Error while logout', error: error})
	}
}