import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { SignJWT } from 'jose';
import { jwtVerify } from 'jose';

export class StudentF {
	constructor() {
		this.app = new Hono();
		this.app.use('/api/*', cors());
	}

	async getStudent(c, id = null) {
		if (id !== null) {
			try {
			return { data :(await c.env.DATABASE.prepare(
				`SELECT * FROM student WHERE id = ?`
			).bind(id).all()).results, status: "success" };
			} catch (e) {
                console.error('Error processing request:', e.stack);
                return { error: 'student not found',headers: ["id", "name"], status: 'error' };
            }
			// continue here
		} else {
			try {
				const { results } = await c.env.DATABASE.prepare(
					`SELECT * FROM student`
				).all();

				return { data: results, headers: ["id", "name"], status: "success" };
			} catch (e) {
				console.error('Error processing request:', e.stack);
				return { error: 'Internal Server Error', status: 'error' };
			}
		}
	}

	async postStudent(c,name) {
		try {
			return (await c.env.DATABASE.prepare(
				`INSERT INTO student (name) VALUES (?)`
			).bind(name).run());
		} catch (error) {
			console.error('Error processing request:', error.stack);
			return
		}
	}
}
