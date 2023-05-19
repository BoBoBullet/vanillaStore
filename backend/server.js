import express from 'express';
import mysql from 'mysql2'
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';


require('dotenv').config();


const salt = 10;

const app = express();
app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000",
  methods: ["POST", "GET"],
  credentials: true
}));
app.use(cookieParser());

const db = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});




const verifyUser = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.json({ Error: "Vous n'êtes pas authentifié" });
  } else {
    jwt.verify(token.split(' ')[1], "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json({ Error: "Token est incorrect" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

app.get('/', verifyUser, (req, res) => {
  return res.json({ Status: "Success", name: req.name });
});

app.get('/users', (req, res) => {
  const sql = 'SELECT * FROM users';
  db.getConnection((error, connection) => {
    if (error) {
      console.error('Error getting MySQL connection:', error);
      res.status(500).send('Internal server error');
      return;
    }
    connection.query(sql, (error, results) => {
      // release the connection
      connection.release();

      if (error) {
        console.error('Error executing MySQL query:', error);
        res.status(500).send('Internal server error');
        return;
      }

      // send the results back to the client
      res.json(results);
    });
  });
});

app.post('/register', (req, res) => {
  const sql = "INSERT INTO users (`name`, `email`, `password`) VALUES (?, ?, ?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: "Error for hashing password" });
    const values = [
      req.body.name,
      req.body.email,
      hash
    ]
    db.query(sql, values, (err, result) => {
      if (err) return res.json({ Error: "Inserting data Error in server" });
      return res.json({ Status: "Success" })
    })
  })
});

// Login process
app.post('/login', (req, res) => {
  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Login error in server" });
    if (data.length > 0) {
      bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
        if (err) return res.json({ Error: "Password compare error" });
        if (response) {
          const userId = data[0].id; // Retrieve the user ID from the database
          const name = data[0].name;
          const token = jwt.sign({ name }, "jwt-secret-key", { expiresIn: '1d' });

          res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'strict',
            secure: true,
          });

          const userInfo = { userId, name, token }; // Include the user ID and token in the userInfo object

          return res.json({ Status: "Success", userInfo });
        } else {
          return res.json({ Error: "Password not matched" });
        }
      });
    } else {
      return res.json({ Error: "No email existed" });
    }
  });
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ Status: "Success" });
});

app.get('/products', (req, res) => {
  const sql = 'SELECT * FROM products';
  db.query(sql, (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (data.length > 0) {
      console.log(data);
      return res.json(data);
    } else {
      return res.status(404).json({ error: 'No products found' });
    }
  });
});

const sendOrder = (req) => {
  // Access the necessary data from the req object
  const { userId, products } = req.body;

  // Process the order data and perform any necessary operations
  // Example: Send a notification, update inventory, etc.

  console.log('Sending order...');
  console.log('User ID:', userId);
  console.log('Product data:', products);

  // Add your logic here to send the order
  // You can use third-party libraries, APIs, or custom code to send the order

  // Example: Send an email notification
  const emailBody = `Thank you for your order, User ID: ${userId}. Order details: ${JSON.stringify(products)}`;
  const emailOptions = {
    to: 'your-email@example.com',
    subject: 'New Order',
    text: emailBody,
  };

  console.log(emailOptions)
  };


app.post('/orders', verifyUser, (req, res) => {
  const { userId, products } = req.body;

  const newOrder = {
    userId: userId,
    createdAt: new Date(),
  };

  db.query('INSERT INTO orders SET ?', newOrder, (error, result) => {
    if (error) {
      console.error('Error inserting order into database:', error);
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }

    const orderId = result.insertId;

    const orderItems = products.map((product) => ({
      orderId: orderId,
      productId: product.id,
      quantity: product.quantity,
    }));

    db.query(
      'INSERT INTO order_items (orderId, productId, quantity) VALUES ?',
      [orderItems.map((item) => [item.orderId, item.productId, item.quantity])],
      (error, result) => {
        if (error) {
          console.error('Error inserting order items into database:', error);
          res.status(500).json({ error: 'Internal Server Error' });
          return;
        }

        res.json({ status: 'Success', newOrder: orderId });

        // Call the sendOrder function passing the req object
        sendOrder(req);
      }
    );
  });
});


app.listen(8081, () => {
  console.log("Running...");
});