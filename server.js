const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs-extra');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const saltRounds = 10;
const secretKey = 'your-secret-key'; // This should be an environment variable in a real app

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const dbFile = './database.json';
fs.ensureFileSync(dbFile);

function readData() {
  try {
    const data = fs.readFileSync(dbFile, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return { users: [], products: [] };
  }
}

function writeData(data) {
  fs.writeFileSync(dbFile, JSON.stringify(data, null, 2), 'utf8');
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send('Username and password are required.');
    }

    const dbData = readData();
    if (dbData.users.some(user => user.username === username)) {
      return res.status(409).send('User already exists.');
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword,
    };

    dbData.users.push(newUser);
    writeData(dbData);

    res.status(201).send('User created.');
  } catch (error) {
    res.status(500).send('Server error.');
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const dbData = readData();

    const user = dbData.users.find(user => user.username === username);
    if (!user) return res.status(404).send('User not found.');

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send('Password is incorrect.');

    const accessToken = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
    res.send({ accessToken });
  } catch (error) {
    res.status(500).send('Server error.');
  }
});

app.post('/api/products', authenticateToken, (req, res) => {
  try {
    const { name, price } = req.body;
    if (!name || price == null) {
      return res.status(400).send('Product name and price are required.');
    }

    const dbData = readData();
    const product = { id: uuidv4(), name, price };
    dbData.products.push(product);
    writeData(dbData);

    res.status(201).send(product);
  } catch (error) {
    res.status(500).send('Server error.');
  }
});

app.get('/api/products', authenticateToken, (req, res) => {
  try {
    const products = readData().products;
    res.send(products);
  } catch (error) {
    res.status(500).send('Server error.');
  }
});

app.put('/api/products/:id', authenticateToken, (req, res) => {
  try {
    let data = readData();
    let products = data.products;
    let productIndex = products.findIndex(p => p.id === req.params.id);
    if (productIndex === -1) {
      return res.status(404).send('Product not found.');
    }

    products[productIndex] = { ...products[productIndex], ...req.body };
    writeData(data);
    res.send(products[productIndex]);
  } catch (error) {
    res.status(500).send('Server error.');
  }
});

app.delete('/api/products/:id', authenticateToken, (req, res) => {
  try {
    let data = readData();
    let products = data.products;
    let newProducts = products.filter(p => p.id !== req.params.id);
    if (products.length === newProducts.length) {
      return res.status(404).send('Product not found.');
    }
    writeData({ ...data, products: newProducts });
    res.status(204).send();
  } catch (error) {
    res.status(500).send('Server error.');
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});