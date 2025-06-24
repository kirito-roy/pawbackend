FROM node:20

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 3000

# Ensure environment variable is available
ENV NODE_ENV=production

CMD ["npm" , "run" , "dev"]
