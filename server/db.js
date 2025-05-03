const pg = require('pg');
const uuid = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'secret lovers';

const { Client } = pg;
const client = new Client({
  user: 'lhern',
  password: '',
  host: 'localhost',
  port: 5432,
  database: 'lhern',
});

const createTables = async () => {
  const SQL = `
    DROP TABLE IF EXISTS favorites;
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS products;

    CREATE TABLE users(
      id UUID PRIMARY KEY,
      username VARCHAR(20) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    );

    CREATE TABLE products(
      id UUID PRIMARY KEY,
      name VARCHAR(20)
    );

    CREATE TABLE favorites(
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) NOT NULL,
      product_id UUID REFERENCES products(id) NOT NULL,
      CONSTRAINT unique_user_id_and_product_id UNIQUE (user_id, product_id)
    );
  `;
  await client.query(SQL);
};

const createUser = async ({ username, password }) => {
  const hash = await bcrypt.hash(password, 5);
  const SQL = `
    INSERT INTO users(id, username, password)
    VALUES($1, $2, $3) RETURNING id, username;
  `;
  const response = await client.query(SQL, [uuid.v4(), username, hash]);
  return response.rows[0];
};

const createProduct = async ({ name }) => {
  const SQL = `
    INSERT INTO products(id, name)
    VALUES($1, $2) RETURNING *;
  `;
  const response = await client.query(SQL, [uuid.v4(), name]);
  return response.rows[0];
};

const createFavorite = async ({ user_id, product_id }) => {
  const SQL = `
    INSERT INTO favorites(id, user_id, product_id)
    VALUES($1, $2, $3) RETURNING *;
  `;
  const response = await client.query(SQL, [uuid.v4(), user_id, product_id]);
  return response.rows[0];
};

const destroyFavorite = async ({ user_id, id }) => {
  const SQL = `
    DELETE FROM favorites
    WHERE user_id = $1 AND id = $2;
  `;
  await client.query(SQL, [user_id, id]);
};

const authenticate = async ({ username, password }) => {
  const SQL = `SELECT * FROM users WHERE username = $1`;
  const response = await client.query(SQL, [username]);
  const user = response.rows[0];
  if (!user) {
    const error = Error('not authorized');
    error.status = 401;
    throw error;
  }
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    const error = Error('not authorized');
    error.status = 401;
    throw error;
  }
  return { token: jwt.sign({ id: user.id }, JWT_SECRET) };
};

const findUserWithToken = async (token) => {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const SQL = `SELECT id, username FROM users WHERE id = $1`;
    const response = await client.query(SQL, [payload.id]);
    if (!response.rows.length) {
      throw Error('not authorized');
    }
    return response.rows[0];
  } catch (err) {
    const error = Error('not authorized');
    error.status = 401;
    throw error;
  }
};

const fetchUsers = async () => {
  const SQL = `SELECT id, username FROM users`;
  const response = await client.query(SQL);
  return response.rows;
};

const fetchProducts = async () => {
  const SQL = `SELECT * FROM products`;
  const response = await client.query(SQL);
  return response.rows;
};

const fetchFavorites = async (user_id) => {
  const SQL = `SELECT * FROM favorites WHERE user_id = $1`;
  const response = await client.query(SQL, [user_id]);
  return response.rows;
};

module.exports = {
  client,
  createTables,
  createUser,
  createProduct,
  fetchUsers,
  fetchProducts,
  fetchFavorites,
  createFavorite,
  destroyFavorite,
  authenticate,
  findUserWithToken
};
