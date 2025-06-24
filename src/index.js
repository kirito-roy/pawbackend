import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { SignJWT, jwtVerify, createRemoteJWKSet } from 'jose';
import { StudentF } from './functions/studentF.js';
import { JWTClass } from './functions/createJwt.js';
import { serve } from '@hono/node-server';
import postgres from 'postgres';

import 'dotenv/config'; // optional if running locally
import { env } from 'process';

const app = new Hono();
const studentF = new StudentF();
const jwtClass = new JWTClass();
app.use(
	'/api/*',
	cors(/*{
		origin: '*', // For development only, avoid in production
		allowHeaders: ['Authorization', 'Content-Type'],
		allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
	}*/)
);

function getDatabaseUrl(c) {
	return c?.env?.HYPERDRIVE?.connectionString || process.env.DATABASE_URL;
}

app.use('*', async (c, next) => {
	const connStr = getDatabaseUrl(c);
	if (!connStr) {
		console.error('❌ No valid DB connection string');
		c.env.DB_AVAILABLE = false;
		return await next();
	}

	// Initialize SQL client
	const sql = postgres(connStr, {
		max: 5,
		fetch_types: false,
	});

	c.env.SQL = sql;
	c.env.DB_AVAILABLE = true;

	await next(); // ⚠️ Only one next()

	// Safe cleanup
	if (typeof sql.end === 'function') {
		try {
			await sql.end(); // 🚫 Don't use executionCtx in Node
		} catch (cleanupErr) {
			console.warn('⚠️ Error during SQL cleanup:', cleanupErr.message);
		}
	}
});





app.get("api/echo", async c => {
	try {
		// multiple input 
		// const {name,roll} = c.req.query('name',"roll");
		const name = c.req.query('name');
		const roll = c.req.query('roll');
		if (!name || !roll) {
			return c.json({ error: "Missing 'data' value" }, 400);
		}
		return c.json({ name: name, roll: roll }, 200);
	} catch (error) {
		console.error('Error processing request:', error.stack);
		return c.json({ error: 'Internal Server Error', details: error.message }, 500);
	}
}
);
app.post("api/admin/dataentry", async c => {
	try {
		const { authorization } = c.req.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}
		const token = authHeader.split(' ')[1];
		const secret = c.env.SECRET_KEY;

		// Verify token
		const payload = await jwtClass.verifyToken(token, secret);
		let { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(payload.email).all();
		if (results.length === 0) {
			return c.json({ error: "User not found" }, 404);
		} else {
			try {
				const { productCategory, productDescription, productName, productPrice, productImage } = await c.req.json();
				if (!productCategory || !productDescription || !productName || !productPrice || !productImage) {
					return c.json({ error: "Missing 'productCategory' or 'productDescription' or 'productName' or 'productPrice' or 'productImage' value for update" }, 400);
				}
				let { success } = await c.env.DATABASE.prepare(
					'INSERT INTO products (productCategory, productDescription, productName, productPrice, productImage) VALUES (?, ?, ?, ?, ?)'
				).bind(productCategory, productDescription, productName, productPrice, productImage).all();
				if (!success) {
					return c.json({ error: "Product not inserted" }, 404);
				} else {
					return c.json({ message: "Product added successfully" }, 201);
				}

			}
			catch (error) {
				console.error('Error processing request:', error.stack);
				return c.json({ error: 'Internal Server Error from dataentry inner try', details: error.message }, 500);
			}
		}
	} catch (e) {
		console.error('Error processing request:', e.stack);
		return c.json({ error: 'Internal Server Error', details: e.message }, 500);
	}
}
);
app.get('api/admin/getProducts', async c => {
	try {
		const { authorization } = c.req.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}
		const token = authHeader.split(' ')[1];
		const secret = c.env.SECRET_KEY;

		// Verify token
		const payload = await jwtClass.verifyToken(token, secret);
		let { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(payload.email).all();
		if (results.length === 0) {
			return c.json({ error: "User not found" }, 404);
		} else {
			let { results } = await c.env.DATABASE.prepare(
				'SELECT * FROM products'
			).all();
			if (results.length === 0) {
				return c.json({ error: "Products not found", status: "failed" }, 404);
			} else {
				return c.json({ result: results, status: "success" }, 201);
			}
		}
	} catch (e) {
		console.error('Error processing request:', e.stack);
		return c.json({ error: 'Internal Server Error', details: e.message }, 500);
	}
}
);

app.get('api/user/Details', async c => {
	try {
		const { authorization } = c.req.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}
		const token = authHeader.split(' ')[1];
		const secret = c.env.SECRET_KEY;

		// Verify token
		const payload = await jwtClass.verifyToken(token, secret);
		const { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(payload.email).all();
		if (results.length === 0) {
			return c.json({ error: "User not found" }, 404);
		} else {

			return c.json({
				result: {
					id: results[0].id,
					username: results[0].username,
					email: results[0].email,
					role: results[0].role,
					profile_picture: results[0].profile_picture,
					phoneNumber: results[0].phone_number || null,
				}, message: "successfully retreved data"
			}, 201);
		}
	} catch (e) {
		console.error('Error processing request:', e.stack);
		return c.json({ error: 'Internal Server Error', details: e.message }, 500);
	}
})
app.post('api/user/updateDatails', async c => {
	try {
		const { authorization } = c.req.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}
		const token = authHeader.split(' ')[1];
		const secret = c.env.SECRET_KEY;

		// Verify token
		const payload = await jwtClass.verifyToken(token, secret);
		const { results } = await c.env.DATABASE.prepare(
			'SELECT * FROM user WHERE email = ?'
		).bind(payload.email).all();
		if (results.length === 0) {
			return c.json({ error: "User not found" }, 404);
		} else {
			const { username, phoneNumber } = await c.req.json();
			if (!username || !phoneNumber) {
				return c.json({ error: "Missing 'username' or 'phone number' value for update" }, 400);
			}


			const results1 = await c.env.DATABASE.prepare(
				'UPDATE user SET username = ?, phone_number = ? WHERE email = ?'
			).bind(username, phoneNumber, payload.email).all();

			return c.json({ message: "User updated successfully" }, 201);
		}
	} catch (error) {
		console.error('Error processing request:', error.stack);
		return c.json({ error: 'Internal Server Error', details: error.message }, 500);
	}
}
);

app.get('api/search', async c => {
	try {
		const { authorization } = c.req.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}
		const token = authHeader.split(' ')[1];
		const secret = c.env.SECRET_KEY;

		// Verify token
		const payload = await jwtClass.verifyToken(token, secret);
		const { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(payload.email).all();
		if (results.length === 0) {
			return c.json({ error: "User not found" }, 404);
		} else {
			const data = c.req.query('data');
			if (!data) {
				return c.json({ error: "Missing 'data' value for search" }, 400);
			}

			const results1 = await c.env.DATABASE.prepare(
				`insert into searches (email, search) values (?, ?)`
			).bind(payload.email, data).all();

			return c.json({ message: "Search saved successfully" }, 201);
		}


	} catch {

	}
}
);
app.get('api/searched', async c => {
	try {
		const { authorization } = c.req.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}
		const token = authHeader.split(' ')[1];
		const secret = c.env.SECRET_KEY;

		// Verify token
		const payload = await jwtClass.verifyToken(token, secret);
		const { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(payload.email).all();
		if (results.length === 0) {
			return c.json({ error: "User not found" }, 404);
		} else {
			const { results } = await c.env.DATABASE.prepare(
				`SELECT search FROM searches WHERE email = ? GROUP BY search ORDER BY MAX(id) DESC LIMIT 5;`
			).bind(payload.email).all();

			return c.json({ result: results }, 201);
		}
	} catch {

	}
}
);

app.get('/api/hello', async c => {
	try {
		const { authorization } = c.req.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}
		const token = authHeader.split(' ')[1];
		const secret = c.env.SECRET_KEY;

		// Verify token
		const payload = await jwtClass.verifyToken(token, secret);

		try {
			const id = c.req.query('id');
			// Perform the database query
			const { results } = await c.env.DATABASE.prepare(
				`SELECT * FROM student WHERE id = ?`
			).bind(id).all();

			// Return the results as JSON
			return c.json({ data: results[0], headers: ["id", "name"], status: "success" }, 200);

		} catch (error) {
			// Log the error for debugging purposes
			try {
				// Perform the database query
				const { results } = await c.env.DATABASE.prepare(
					`SELECT * FROM student` // Ensure 'student' is the correct table name
				).all();

				// Return the results as JSON
				return c.json({ data: results, headers: ["id", "name"], status: "success" }, 200);
			} catch (e) {
				console.error('Error processing request:', e.stack);
				return c.json({ error: 'Internal Server Error', details: e.message }, 500);
			}
		}
	} catch (error) {
		console.error('Error verifying token:', error);
		return c.json({ error: 'Invalid token' }, 401);
	}
});





app.post('/api/hello', async c => {

	try {
		const abc = c.req;
		const { authorization } = abc.header();
		const authHeader = authorization;
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return c.json({ error: 'Unauthorized' }, 401);
		}

		const { name } = await c.req.json();
		// return c.json({ message: 'Hello, world!', name }, 200);


		if (!name) {
			return c.json({ error: "Missing 'name' value for new entry" }, 400);
		}

		// Insert the new entry into the database
		const { success } = await studentF.postStudent(c, name);

		if (success) {
			return c.json({ message: "Entry saved successfully" }, 201);
		} else {
			throw new Error("Database insertion failed");
		}

	} catch (error) {
		// Log the error for debugging purposes
		console.error('Error processing request:', error.stack);
		return c.json({ error: 'enter data properly' }, 500);
	}
});
// register user
// register user
// Use Google's public JWKs for verifying ID tokens
// const GOOGLE_JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

// // Your Google Web Client ID (not service account client ID)
// const GOOGLE_CLIENT_ID = '153275426304-nl8jro5tvf8j8ggk7gj8h4na2g5h54k1.apps.googleusercontent.com';
// const GOOGLE_PROJECT_ID = 'pawpawsy'; // your Firebase project ID
// const GOOGLE_ISSUER = `https://securetoken.google.com/${GOOGLE_PROJECT_ID}`;
// const GOOGLE_JWKS = createRemoteJWKSet(
//   new URL('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com')
// );

app.post('/api/user/google-login', async (c) => {
	try {
		const { uid, displayName, createdAt, email, emailVerified, photoURL } = await c.req.json();
		if (!uid || !displayName || !createdAt || !email || !emailVerified || !photoURL) {
			return c.json({ error: 'Missing required fields for Google login' }, 400);
		}
		const { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(email).all();

		let payload;
		if (results.length > 0) {
			const user = results[0];
			payload = {
				id: user.id,
				username: user.username,
				email: user.email,
				role: user.role,
				// make the exp 7 days
				exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 // Token expires in 7 days
				// exp: Math.floor(Date.now() / 1000) + 3600 // Token expires in 1 hour
			};
		} else {
			const { success } = await c.env.DATABASE.prepare(
				`INSERT INTO user (username, email, password, role, created_at,profile_picture) VALUES (?, ?, ?, ?, ?,?)`
			).bind(displayName, email, uid, 'user', createdAt, photoURL).run();
			if (!success) {
				throw new Error("Failed to insert user into database");
			}


			// Prepare the JWT payload with user information
			payload = {
				id: uid,
				username: displayName,
				email: email,
				role: "user",
				// make the exp 7 days
				exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 // Token expires in 7 days
				// exp: Math.floor(Date.now() / 1000) + 3600 // Token expires in 1 hour
			};
		}
		// Get the secret key from environment variables
		const secret = c.env.SECRET_KEY;

		// Generate the JWT token using HS256
		const token = await new SignJWT(payload)
			.setProtectedHeader({ alg: 'HS256' })
			.sign(new TextEncoder().encode(secret));

		// Return the JWT token and user information
		return c.json({
			message: "Login successful",
			token,
			user: {
				id: payload.id,
				username: payload.username,
				email: payload.email,
				role: payload.role
			}
		}, 200);

	} catch (e) {
		console.error('Error processing request:', e.stack);
		return c.json({ error: 'Internal Server Error', details: e.message }, 500);
	}


});
app.post('/api/user/login', async c => {
	try {
		// Get email and password from frontend
		const { email, password } = await c.req.json();

		// Check if email or password is missing
		if (!email || !password) {
			return c.json({ error: "Missing 'email' or 'password' value for login" }, 400);
		}

		// Check if user exists in the database
		const { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(email).all();

		if (results.length === 0) {
			return c.json({ error: "User not found" }, 404);
		}

		const user = results[0];

		// Check if the password is correct
		if (user.password !== password) {
			return c.json({ error: "Invalid password" }, 401);
		}

		// Prepare the JWT payload with user information
		const payload = {
			id: user.id,
			username: user.username,
			email: user.email,
			role: user.role,
			// make the exp 7 days
			exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 // Token expires in 7 days
			// exp: Math.floor(Date.now() / 1000) + 3600 // Token expires in 1 hour
		};

		// Get the secret key from environment variables
		const secret = c.env.SECRET_KEY;

		// Generate the JWT token using HS256
		const token = await new SignJWT(payload)
			.setProtectedHeader({ alg: 'HS256' })
			.sign(new TextEncoder().encode(secret));

		// Return the JWT token and user information
		return c.json({
			message: "Login successful",
			token,
			user: {
				id: user.id,
				username: user.username,
				email: user.email,
				role: user.role
			}
		}, 200);
	} catch (error) {
		console.error('Error during login:', error.stack);
		return c.json({ error: 'Internal Server Error', details: error.message }, 500);
	}
});
app.post('/api/user/signup', async c => {
	try {
		// Get user details from frontend
		const { username, email, password } = await c.req.json();

		// Check if all required fields are provided
		if (!username || !email || !password) {
			return c.json({ error: "Missing required fields: 'username', 'email', or 'password'" }, 400);
		}

		// Check if the user already exists in the database
		const { results } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ? OR username = ?`
		).bind(email, username).all();

		// If user already exists, return error
		if (results.length > 0) {
			return c.json({ error: "User already exists with this email or username" }, 409);
		}

		// Insert the new user into the database
		const { success } = await c.env.DATABASE.prepare(
			`INSERT INTO user (username, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)`
		).bind(username, email, password, 'user', new Date().toISOString()).run();

		if (!success) {
			throw new Error("Failed to insert user into database");
		}

		// Get the inserted user's data
		const { results: newUser } = await c.env.DATABASE.prepare(
			`SELECT * FROM user WHERE email = ?`
		).bind(email).all();

		const user = newUser[0];

		// Prepare JWT payload
		const payload = {
			id: user.id,
			username: user.username,
			email: user.email,
			role: user.role,
			exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 // Token expires in 1 hour
		};

		// Get the secret key from environment
		const secret = c.env.SECRET_KEY;

		// Generate JWT token
		const token = await new SignJWT(payload)
			.setProtectedHeader({ alg: 'HS256' })
			.sign(new TextEncoder().encode(secret));

		// Return token and user data
		return c.json({
			message: "User registered successfully",
			token,
			user: {
				id: user.id,
				username: user.username,
				email: user.email,
				role: user.role,
			},
		}, 201);
	} catch (error) {
		console.error('Error during signup:', error.stack);
		return c.json({ error: 'Internal Server Error', details: error.message }, 500);
	}
});



// send otp
// send otp not done yet
app.post('/api/sendotp', async c => {
	try {
		const { phoneNumber } = await c.req.json();
		if (!phoneNumber) {
			return c.json({ error: "Missing 'phoneNumber' value for OTP" }, 400);
		}

		// Access environment variables
		const accountSid = c.env.TWILIO_ACCOUNT_SID;
		const authToken = c.env.TWILIO_AUTH_TOKEN;
		const serviceSid = c.env.TWILIO_SERVICE_SID;

		// return c.json({ m1:{ accountSid}, m2:{ authToken} }, 200);

		const url = `https://verify.twilio.com/v2/Services/${serviceSid}/Verifications`;

		const body = new URLSearchParams();
		body.append('To', phoneNumber);
		body.append('Channel', 'sms');

		const response = await fetch(url, {
			method: 'POST',
			headers: {
				'Authorization': `Basic ${btoa(`${accountSid}:${authToken}`)}`,
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			body: body
		});

		if (response.ok) {
			return c.json({ message: "OTP sent successfully" }, 200);
		} else {
			const errorData = await response.json();
			return c.json({ error: "Failed to send OTP", details: errorData }, 500);
		}
	} catch (error) {
		console.error('Error processing request:', error.stack);
		return c.json({ error: 'Internal Server Error', details: error.message }, 500);
	}
});

// test jwt token


// Register the fetch event
// export default {
// 	async fetch(request, env, ctx) {
// 		return app.fetch(request, env, ctx);
// 	}
// };

const productionenv = process.env.env || 'production';
if (productionenv === 'local') {
	const port = process.env.PORT || 3000;

	serve({ fetch: app.fetch, port });

	console.log(`🚀 Server is running on http://localhost:${port}`);
}

export default {
	async fetch(request, env, ctx) {
		return app.fetch(request, env, ctx);
	}
};
