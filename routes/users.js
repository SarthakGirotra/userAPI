import express from 'express'

import { login, signup, home } from '../controllers/users.js'

const router = express.Router();

router.post('/login', login)
router.post('/signup', signup)
router.post('/home', home)

export default router;