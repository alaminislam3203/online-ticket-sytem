const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

const app = express();

// ============================================================
// Firebase Admin Initialization
// ============================================================
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString(
  'utf-8',
);
const serviceAccountDecoded = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountDecoded),
});

// ============================================================
// Global Middleware
// ============================================================
app.use(cors());
app.use(express.json());

// ============================================================
// MongoDB Connection URI
// ============================================================
const uri = `mongodb+srv://voyago_db_user2:${process.env.DB_PASS}@cluster0.pbml03e.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ============================================================
// JWT Middleware - Verifies the Bearer token from request header
// ============================================================
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return res.status(403).json({ message: 'Forbidden: Invalid token' });
    }
    req.user = decodedToken;
    next();
  });
};

// ============================================================
// Role-based Middleware - Only allows admin users
// ============================================================
const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access only' });
  }
  next();
};

// ============================================================
// Role-based Middleware - Only allows vendor users
// ============================================================
const verifyVendor = (req, res, next) => {
  if (req.user?.role !== 'vendor') {
    return res.status(403).json({ message: 'Vendor access only' });
  }
  next();
};

// ============================================================
// Main async function
// ============================================================
async function run() {
  try {
    await client.connect();

    const db = client.db('voyago_db');

    const usersCollection = db.collection('users');
    const ticketsCollection = db.collection('tickets');
    const bookingCollection = db.collection('booking');
    const transactionsCollection = db.collection('transactions');

    console.log('MongoDB connected successfully!');

    // ==========================================================
    // AUTH ROUTES
    // ==========================================================

    // Register a new user with hashed password
    app.post('/api/register', async (req, res) => {
      try {
        const { name, email, password } = req.body;

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await usersCollection.insertOne({
          name,
          email,
          password: hashedPassword,
          role: 'user',
          createdAt: new Date(),
        });

        res.status(201).json({ message: 'User registered successfully' });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Login user and return a signed JWT token
    app.post('/api/login', async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(401).json({ message: 'Incorrect password' });
        }

        const token = jwt.sign(
          { email: user.email, id: user._id, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '15d' },
        );

        res.json({ token, role: user.role, email: user.email });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.get('/api/me', verifyToken, async (req, res) => {
      try {
        const user = await usersCollection.findOne(
          { _id: new ObjectId(req.user.id) },
          { projection: { password: 0 } },
        );
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // ==========================================================
    // USER ROUTES
    // ==========================================================

    app.get('/users/role/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email && req.user.role !== 'admin') {
          return res.status(403).json({ message: 'Forbidden' });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: 'User not found' });
        res.send({ role: user.role });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // ==========================================================
    // ADMIN ROUTES
    // ==========================================================

    app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const users = await usersCollection
          .find({}, { projection: { password: 0 } })
          .toArray();
        res.json(users);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Make a user Admin
    app.patch(
      '/api/admin/users/make-admin/:id',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role: 'admin' } },
          );
          res.json(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Make a user Vendor
    app.patch(
      '/api/admin/users/make-vendor/:id',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role: 'vendor' } },
          );
          res.json(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Mark vendor as fraud - hide all their tickets & prevent adding new ones
    app.patch(
      '/api/admin/users/mark-fraud/:id',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;

          // Get vendor email first
          const vendor = await usersCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!vendor) {
            return res.status(404).json({ message: 'User not found' });
          }
          if (vendor.role !== 'vendor') {
            return res.status(400).json({ message: 'User is not a vendor' });
          }

          // Mark user as fraud
          await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { isFraud: true } },
          );

          // Hide all tickets by this vendor
          await ticketsCollection.updateMany(
            { vendorEmail: vendor.email },
            { $set: { isHidden: true } },
          );

          res.json({ message: 'Vendor marked as fraud and tickets hidden' });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    app.get(
      '/api/admin/payments',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const payments = await transactionsCollection
            .find({})
            .sort({ date: -1 })
            .toArray();
          res.status(200).json(Array.isArray(payments) ? payments : []);
        } catch (error) {
          res.status(500).json([]);
        }
      },
    );

    app.post(
      '/api/admin/payments',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { email, amount, transactionId } = req.body;

          if (!email || !amount) {
            return res.status(400).json({ message: 'Missing required fields' });
          }

          const result = await transactionsCollection.insertOne({
            email,
            amount,
            transactionId,
            createdAt: new Date(),
          });

          res.status(201).json(result);
        } catch (error) {
          res.status(500).json({ message: 'Insert failed' });
        }
      },
    );

    // Admin approves a ticket
    app.patch(
      '/api/tickets/status/:id',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { status } = req.body;

          const allowed = ['approved', 'rejected', 'pending'];
          if (!allowed.includes(status)) {
            return res.status(400).json({ message: 'Invalid status value' });
          }

          const result = await ticketsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { verificationStatus: status } },
          );
          res.send(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Admin toggles advertisement for a ticket
    // Max 6 tickets can be advertised at a time
    app.patch(
      '/api/admin/tickets/advertise/:id',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { isAdvertised } = req.body;

          if (isAdvertised) {
            // Check current advertised count
            const advertisedCount = await ticketsCollection.countDocuments({
              isAdvertised: true,
            });
            if (advertisedCount >= 6) {
              return res.status(400).json({
                message: 'Cannot advertise more than 6 tickets at a time',
              });
            }
          }

          const result = await ticketsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { isAdvertised } },
          );
          res.json(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Get all admin-approved tickets for advertise management
    app.get(
      '/api/admin/tickets',
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const tickets = await ticketsCollection
            .find({ verificationStatus: 'approved' })
            .toArray();
          res.json(tickets);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // ==========================================================
    // VENDOR ROUTES
    // ==========================================================

    app.post(
      '/api/vendor/tickets',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          // Check if vendor is marked as fraud
          const vendor = await usersCollection.findOne({
            email: req.user.email,
          });
          if (vendor?.isFraud) {
            return res
              .status(403)
              .json({ message: 'Fraud vendors cannot add tickets' });
          }

          const ticket = req.body;
          const result = await ticketsCollection.insertOne({
            ...ticket,
            vendorEmail: req.user.email,
            verificationStatus: 'pending',
            isAdvertised: false,
            isHidden: false,
            createdAt: new Date(),
          });
          res.json(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Get vendor's own tickets
    app.get(
      '/api/vendor/tickets',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          const tickets = await ticketsCollection
            .find({ vendorEmail: req.user.email })
            .sort({ createdAt: -1 })
            .toArray();
          res.json(tickets);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Update a ticket (vendor can update their own tickets)
    app.put(
      '/api/vendor/tickets/:id',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          const id = req.params.id;
          const updateData = req.body;

          // Make sure vendor owns this ticket
          const ticket = await ticketsCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
          }
          if (ticket.vendorEmail !== req.user.email) {
            return res.status(403).json({ message: 'Forbidden' });
          }
          if (ticket.verificationStatus === 'rejected') {
            return res
              .status(400)
              .json({ message: 'Cannot update a rejected ticket' });
          }

          // Remove protected fields from update
          delete updateData._id;
          delete updateData.vendorEmail;
          delete updateData.verificationStatus;
          delete updateData.isAdvertised;

          const result = await ticketsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { ...updateData, updatedAt: new Date() } },
          );
          res.json(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Delete a ticket (vendor can delete their own tickets)
    app.delete(
      '/api/vendor/tickets/:id',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          const id = req.params.id;

          const ticket = await ticketsCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
          }
          if (ticket.vendorEmail !== req.user.email) {
            return res.status(403).json({ message: 'Forbidden' });
          }
          if (ticket.verificationStatus === 'rejected') {
            return res
              .status(400)
              .json({ message: 'Cannot delete a rejected ticket' });
          }

          const result = await ticketsCollection.deleteOne({
            _id: new ObjectId(id),
          });
          res.json(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // Vendor views booking requests for their tickets
    app.get(
      '/api/requested-booking',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          // Get vendor's ticket IDs
          const vendorTickets = await ticketsCollection
            .find({ vendorEmail: req.user.email }, { projection: { _id: 1 } })
            .toArray();

          const ticketIds = vendorTickets.map(t => t._id.toString());

          // Only return bookings for vendor's own tickets
          const result = await bookingCollection
            .find({ ticketId: { $in: ticketIds } })
            .toArray();
          res.send(result);
        } catch (error) {
          res.status(500).send({ error: error.message });
        }
      },
    );

    // Vendor accepts a booking request
    app.patch(
      '/api/requested-booking/approve/:id',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          const id = req.params.id;

          // Ensure vendor owns the ticket related to this booking
          const booking = await bookingCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!booking) {
            return res.status(404).json({ message: 'Booking not found' });
          }

          const ticket = await ticketsCollection.findOne({
            _id: new ObjectId(booking.ticketId),
          });
          if (!ticket || ticket.vendorEmail !== req.user.email) {
            return res.status(403).json({ message: 'Forbidden' });
          }

          const result = await bookingCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: 'Approved' } },
          );
          res.send(result);
        } catch (error) {
          res.status(500).send({ error: error.message });
        }
      },
    );

    // Vendor rejects a booking request
    app.patch(
      '/api/requested-booking/reject/:id',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          const id = req.params.id;

          const booking = await bookingCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!booking) {
            return res.status(404).json({ message: 'Booking not found' });
          }

          const ticket = await ticketsCollection.findOne({
            _id: new ObjectId(booking.ticketId),
          });
          if (!ticket || ticket.vendorEmail !== req.user.email) {
            return res.status(403).json({ message: 'Forbidden' });
          }

          const result = await bookingCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: 'Rejected' } },
          );
          res.send(result);
        } catch (error) {
          res.status(500).send({ error: error.message });
        }
      },
    );

    // Vendor revenue overview stats
    app.get(
      '/api/vendor/revenue',
      verifyToken,
      verifyVendor,
      async (req, res) => {
        try {
          const vendorEmail = req.user.email;

          const vendorTickets = await ticketsCollection
            .find({ vendorEmail }, { projection: { _id: 1 } })
            .toArray();
          const ticketIds = vendorTickets.map(t => t._id.toString());

          const paidBookings = await bookingCollection
            .find({ ticketId: { $in: ticketIds }, status: 'paid' })
            .toArray();

          const totalRevenue = paidBookings.reduce(
            (sum, b) => sum + (b.price || 0),
            0,
          );
          const totalTicketsSold = paidBookings.reduce(
            (sum, b) => sum + (b.quantity || 1),
            0,
          );
          const totalTicketsAdded = vendorTickets.length;

          res.json({ totalRevenue, totalTicketsSold, totalTicketsAdded });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      },
    );

    // ==========================================================
    // TICKET ROUTES (Public)
    // ==========================================================

    // Get all approved, non-hidden tickets (with optional search & filter)
    app.get('/api/tickets', async (req, res) => {
      try {
        const { from, to, transport, sort, page = 1, limit = 9 } = req.query;

        const query = {
          verificationStatus: 'approved',
          isHidden: { $ne: true },
        };

        if (from) query.from = { $regex: from, $options: 'i' };
        if (to) query.to = { $regex: to, $options: 'i' };
        if (transport) query.busType = { $regex: transport, $options: 'i' };

        let sortOption = { createdAt: -1 };
        if (sort === 'price_asc') sortOption = { price: 1 };
        if (sort === 'price_desc') sortOption = { price: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await ticketsCollection.countDocuments(query);

        const tickets = await ticketsCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.send({
          tickets,
          total,
          page: parseInt(page),
          limit: parseInt(limit),
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Get advertised tickets for homepage
    app.get('/api/tickets/advertised', async (req, res) => {
      try {
        const tickets = await ticketsCollection
          .find({
            isAdvertised: true,
            verificationStatus: 'approved',
            isHidden: { $ne: true },
          })
          .limit(6)
          .toArray();
        res.json(tickets);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Get latest tickets for homepage
    app.get('/api/tickets/latest', async (req, res) => {
      try {
        const tickets = await ticketsCollection
          .find({
            verificationStatus: 'approved',
            isHidden: { $ne: true },
          })
          .sort({ createdAt: -1 })
          .limit(8)
          .toArray();
        res.json(tickets);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.get('/api/tickets/:id', async (req, res) => {
      try {
        const ticket = await ticketsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });
        if (!ticket) {
          return res.status(404).json({ message: 'Ticket not found' });
        }
        res.json(ticket);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // NOTE: This open POST /api/tickets duplicates /api/vendor/tickets.
    // Consider removing this or restricting it — left as-is to avoid breaking changes.
    app.post('/api/tickets', async (req, res) => {
      try {
        const ticket = req.body;
        ticket.verificationStatus = 'pending';
        ticket.isAdvertised = false;
        ticket.isHidden = false;
        const result = await ticketsCollection.insertOne(ticket);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // ==========================================================
    // BOOKING ROUTES
    // ==========================================================

    app.get('/bookings/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email && req.user.role !== 'admin') {
          return res.status(403).json({ message: 'Forbidden' });
        }

        const result = await bookingCollection.find({ email }).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch bookings' });
      }
    });

    // Cancel a booking (only if still pending / vendor hasn't accepted yet)
    app.delete('/api/booking/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const booking = await bookingCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!booking) {
          return res.status(404).json({ message: 'Booking not found' });
        }
        if (booking.email !== req.user.email) {
          return res.status(403).json({ message: 'Forbidden' });
        }
        if (booking.status !== 'pending' && booking.status !== 'Pending') {
          return res
            .status(400)
            .json({ message: 'Can only cancel pending bookings' });
        }

        const result = await bookingCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: 'Failed to cancel booking' });
      }
    });

    app.post('/api/booking', verifyToken, async (req, res) => {
      try {
        const booking = req.body;
        const result = await bookingCollection.insertOne(booking);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to book ticket' });
      }
    });

    // Confirm booking after Stripe payment is verified
    app.post('/api/confirm-booking', async (req, res) => {
      const { sessionId } = req.body;

      try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status === 'paid') {
          const exists = await bookingCollection.findOne({ sessionId });
          if (exists) {
            return res.send({ success: true, message: 'Already saved' });
          }

          const quantity = parseInt(session.metadata.quantity) || 1;

          const bookingData = {
            sessionId,
            ticketId: session.metadata.ticketId,
            customerName: session.customer_email,
            email: session.customer_email,
            from: session.metadata.from,
            to: session.metadata.to,
            busType: session.metadata.busType,
            quantity,
            price: session.amount_total / 100,
            status: 'paid',
            adminStatus: 'pending',
            createdAt: new Date(),
          };

          const result = await bookingCollection.insertOne(bookingData);

          // Reduce ticket quantity after successful payment
          await ticketsCollection.updateOne(
            { _id: new ObjectId(session.metadata.ticketId) },
            { $inc: { quantity: -quantity } },
          );

          res.send({ success: true, result });
        } else {
          res.status(400).send({ error: 'Payment not completed' });
        }
      } catch (error) {
        res.status(500).send({ error: 'Booking confirmation failed' });
      }
    });

    // ==========================================================
    // STRIPE PAYMENT ROUTES
    // ==========================================================

    app.post('/create-checkout-session', verifyToken, async (req, res) => {
      try {
        const { ticketId, quantity = 1 } = req.body;

        // Use email from verified token, not from request body
        const verifiedEmail = req.user.email;

        const ticket = await ticketsCollection.findOne({
          _id: new ObjectId(ticketId),
        });

        if (!ticket) {
          return res.status(404).json({ message: 'Ticket not found' });
        }

        // Validate quantity
        if (quantity > ticket.quantity) {
          return res.status(400).json({
            message: 'Requested quantity exceeds available tickets',
          });
        }

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const maxDate = new Date();
        maxDate.setDate(today.getDate() + 7);
        maxDate.setHours(23, 59, 59, 999);

        const travelDate = new Date(ticket.departureDate + 'T00:00:00');

        if (travelDate < today) {
          return res.status(400).json({ message: 'Cannot book a past date' });
        }

        if (travelDate > maxDate) {
          return res.status(400).json({
            message: 'You can only book within the next 7 days',
          });
        }

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          customer_email: verifiedEmail,
          metadata: {
            ticketId: ticket._id.toString(),
            from: ticket.from,
            to: ticket.to,
            busType: ticket.busType,
            quantity: quantity.toString(),
            title: ticket.title,
          },
          line_items: [
            {
              price_data: {
                currency: 'usd',
                product_data: { name: ticket.title },
                unit_amount: ticket.price * 100,
              },
              quantity,
            },
          ],
          mode: 'payment',
          success_url: `${process.env.DOMAIN_STRIPE}/stripe/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.DOMAIN_STRIPE}/stripe/cancel`,
        });

        res.json({ url: session.url });
      } catch (error) {
        console.error('Stripe session error:', error);
        res.status(500).json({ error: 'Payment session creation failed' });
      }
    });

    // Save transaction after successful Stripe payment
    app.post('/save-transaction', async (req, res) => {
      try {
        const { sessionId } = req.body;

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        // Prevent duplicate transaction records for same session
        const exists = await transactionsCollection.findOne({
          transactionId: session.id,
        });
        if (exists) {
          return res.json({ success: true, message: 'Already saved' });
        }

        const transaction = {
          email: session.customer_email,
          title: session.metadata?.title,
          ticketId: session.metadata?.ticketId,
          amount: session.amount_total / 100,
          transactionId: session.id,
          date: new Date(),
        };

        await transactionsCollection.insertOne(transaction);
        res.json({ success: true });
      } catch (error) {
        console.error('Transaction save error:', error);
        res.status(500).json({ error: 'Failed to save transaction' });
      }
    });

    app.get('/transactions/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email && req.user.role !== 'admin') {
          return res.status(403).json({ message: 'Forbidden' });
        }

        const result = await transactionsCollection.find({ email }).toArray();
        res.send(result);
      } catch (error) {
        console.error('Transaction fetch error:', error);
        res.status(500).send([]);
      }
    });

    // ==========================================================
    // HEALTH CHECK
    // ==========================================================
    app.get('/', (req, res) => {
      res.send('Voyago Server Running 🚀');
    });
  } catch (err) {
    console.error('Failed to connect to MongoDB:', err);
  }
}

run().catch(console.dir);

app.listen(5000, () => {
  console.log('Server running on port 5000');
});
