import express from 'express';
import cors from 'cors';
import mysql from 'mysql2'; // Use mysql2
import bcrypt from 'bcrypt';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import multer from 'multer';
import https from 'https';

import path, { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path'
import dotenv from 'dotenv';
import fs from 'fs'
dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

app.use('/uploads', express.static(join(__dirname, 'uploads')));
app.use(bodyParser.json());
app.use(cors({
origin: 'https://bit-write.com',
methods: ['GET','HEAD','PUT','PATCH','POST','DELETE'],  // Added 'PUT' here

credentials: true,

}));
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/bit-write.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/bit-write.com/fullchain.pem')
};

app.use(cookieParser());
app.use(express.json());
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 86400000 }  // secure should be true in production

}));
const PORT=8083;
const con = mysql.createConnection({
    host: '127.0.0.1',
    user: 'user',
    password: 'password',
    database: 'database', 
});

con.connect(function(err){
    if (err) {
        console.error('Error in connection:', err); 
    } else {
        console.log('Connected');
    }
}
);

function keepConnectionAlive() {
    con.query('SELECT 1', (err) => {
      if (err) {
        console.error('Error pinging the database:', err);
      } else {
        console.log('Database connection alive');
      }
    });
  }
  
  setInterval(keepConnectionAlive, 360000);


app.get('/', (req, res) => {
    if(req.session.email){
        return res.json({valid:true,Email:req.session.email});
    }
    else{
        return res.json({valid:false,Status:"!valid"});
    }
})



app.post('/login', (req, res) => {
    const sql = "SELECT * FROM users WHERE email = ? AND password = ?";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if (err) return res.json({Status: "Error", Error: err});

        if (result.length > 0) {
            req.session.userId = result[0].id; 
            req.session.email = result[0].email;
            return res.json({
                Status: "Success",
                Email: req.session.email,
                PaymentOk: result[0].payment_ok,
                id: result[0].id,
                approved: result[0].approved
            });
        } else {
            return res.json({Status: "Error", Error: "Incorrect Email or Password"});
        }
    });
});
app.delete('/delete-approved-images', (req, res) => {
    // Query the database to fetch the approved work links
    con.query('SELECT id, work_link FROM submitted_work WHERE approved = 1', (err, results) => {
        if (err) {
            console.error('Error fetching approved work links:', err);
            return res.status(500).json({ success: false, message: 'Error fetching approved work links' });
        }

        console.log('Fetched approved work links:', results); // Log fetched data

        // Iterate through the results and delete the corresponding image files
        results.forEach(result => {
            const { work_link } = result;
            const imagePath = path.join(__dirname, work_link);
            console.log('Deleting image at path:', imagePath);

            // Check if the file exists
            if (fs.existsSync(imagePath)) {
                // Delete the file
                fs.unlink(imagePath, (err) => {
                    if (err) {
                        console.error('Error deleting image:', err);
                    } else {
                        console.log('Image deleted successfully:', imagePath);
                    }
                });
            } else {
                console.log('Image not found:', imagePath);
            }
        });

        res.json({ success: true, message: 'Images deleted successfully from the server' });
    });
});




app.post('/register', (req, res) => {
    try {
        const { ref } = req.query; 
        const user = { ...req.body };
        delete user.confirmPassword; 

        console.log('Received registration request:', user);

        const checkEmailSql = "SELECT * FROM users WHERE email = ?";
        con.query(checkEmailSql, [user.email], (err, existingUsers) => {
            if (err) {
                console.error('Error checking email:', err);
                return res.json({ status: 'error', error: 'An error occurred while checking the email' });
            }

            if (existingUsers.length > 0) {
                console.log('Email already registered:', user.email);
                return res.json({ status: 'error', error: 'Email already registered' });
            }

            const registerUser = () => {
                const sql = "INSERT INTO users SET ?";
                con.query(sql, user, (err, result) => {
                    if (err) {
                        console.error('Error registering user:', err);
                        return res.json({ status: 'error', error: 'Failed to register user' });
                    }

                    console.log('User registered successfully:', result);

                    // Update the refer_by field for the user registering
                    if (ref) {
                        user.refer_by = ref; // Add the refer_by field
                        const referralSql = "INSERT INTO referrals (referrer_id, referred_id) VALUES (?, ?)";
                        con.query(referralSql, [ref, result.insertId], (err, referralResult) => {
                            if (err) {
                                console.error('Error recording referral:', err);
                                return res.json({ status: 'error', error: 'Failed to record referral' });
                            }
                            const updateReferBySql = "UPDATE users SET refer_by = ? WHERE id = ?";
                            con.query(updateReferBySql, [ref, result.insertId], (err, updateResult) => {
                                if (err) {
                                    console.error('Error updating refer_by:', err);
                                    return res.json({ status: 'error', error: 'Failed to update refer_by' });
                                }
                                console.log('User registered successfully with referral:', result.insertId, 'Referrer:', ref);
                                return res.json({ status: 'success', message: 'User registered successfully with referral', userId: result.insertId });
                            });
                        });
                    } else {
                        console.log('User registered successfully without referral:', result.insertId);
                        return res.json({ status: 'success', message: 'User registered successfully', userId: result.insertId });
                    }
                });
            };

            if (ref) {
                const checkReferralSql = "SELECT * FROM users WHERE id = ?";
                con.query(checkReferralSql, [ref], (err, referralUsers) => {
                    if (err) {
                        console.error('Error checking referral ID:', err);
                        return res.json({ status: 'error', error: 'Failed to check referral ID' });
                    }

                    if (referralUsers.length === 0) {
                        console.log('Invalid referral ID:', ref);
                        return res.json({ status: 'error', error: 'Invalid referral ID' });
                    }

                    registerUser();
                });
            } else {
                registerUser();
            }
        });
    } catch (error) {
        console.error('Unexpected error:', error);
        return res.json({ status: 'error', error: 'An unexpected error occurred' });
    }
});



async function registerUser(userData, res) {
    // This function will register the user in the database
    const hashedPassword = await bcrypt.hash(userData.password, 10); // Make sure to hash the password before storing it

    const user = {
        ...userData,
        password: hashedPassword
    };

    const sql = "INSERT INTO users SET ?";
    con.query(sql, user, (err, result) => {
        if (err) {
            res.json({status: 'error', error: 'Failed to register user'});
            return;
        }

        res.json({status: 'success', userId: result.insertId});
    });
}

app.get('/approved-referred-users', (req, res) => {
    const userId = req.query.userId;
    if (!userId) {
        return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    const sql = 'SELECT name, approved_at FROM users WHERE refer_by = ? AND approved = 1';

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the users.' });
        }

        res.status(200).json({
            success: true,
            users: result
        });
    });
});
app.post('/payment', (req, res) => {
const { trx_id, sender_name, sender_number, plan, planFees, id } = req.body;
    console.log('Received payment data:', req.body); 
    const payment_ok = 1;
    const rejected = 0;
    

    // Check if the trx_id already exists in the users table
    const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE trx_id = ?';
    con.query(checkQuery, [trx_id], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

        // Inside the '/payment' route
if (checkResults[0].count > 0) {
    // The trx_id already exists; return an error response
    return res.status(400).json({ status: 'error', error: 'Transaction ID already in use' });
  }
  

        // The trx_id doesn't exist; update the user's payment data
        const sql = 'UPDATE users SET trx_id = ?, sender_name = ?, sender_number = ?, payment_ok = ?, rejected = ?, plan = ?, planFees = ? WHERE id = ?';

        con.query(sql, [trx_id, sender_name, sender_number, payment_ok, rejected, plan, planFees, id], (err, result) => {
            if (err) {
                console.error('Error updating payment data:', err);

                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            res.json({ status: 'success' });
        });
    });
});

app.get('/getUserData', (req, res) => {
    if(!req.session.email) {
        return res.json({Status: 'Error', Error: 'User not logged in'});
    }

    const sql = "SELECT * FROM users WHERE email = ?";
    con.query(sql, [req.session.email], (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch user data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result[0]});
        } else {
            return res.json({Status: 'Error', Error: 'User not found'});
        }
    });
});
app.get('/getAllAdmins', (req, res) => {
    const sql = "SELECT * FROM admins";
    con.query(sql, (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch admins data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result});
        } else {
            return res.json({Status: 'Error', Error: 'No admins found'});
        }
    });
});


app.post('/changePassword', (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
  
    const sql = "SELECT password FROM admins WHERE username = ?";
    
    con.query(sql, [username], (err, result) => {
      if (err || result.length === 0) {
        return res.json({ message: 'Username not found' });
      }
  
      const storedPassword = result[0].password;
  
      if (storedPassword !== oldPassword) { 
        return res.json({ message: 'Old password is incorrect' });
      }
  
      const updateSql = "UPDATE admins SET password = ? WHERE username = ?";
      
      con.query(updateSql, [newPassword, username], (updateErr, updateResult) => {
        if (updateErr) {
          return res.json({ message: 'Failed to update password' });
        }
  
        return res.json({ message: 'Password updated successfully' });
      });
    });
  });
  







// Import necessary modules and configure your database connection

app.get('/getPlans', (req, res) => {
    const sql = 'SELECT * FROM plans';
    
    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch plans' });
        }
        
        // Transform results or directly send them to the frontend
        res.json({ status: 'success', plans: results });
    });
});





app.post('/logout', (req, res) => {
    if (req.session) {
        // Destroy session if it exists
        req.session.destroy(err => {
            if (err) {
                return res.json({ Status: 'Error', Error: 'Failed to logout' });
            }

            return res.json({ Status: 'Success', Message: 'Logged out successfully' });
        });
    } else {
        return res.json({ Status: 'Error', Error: 'No session to logout' });
    }
});

app.get('/referrals', async (req, res) => {
    const referrerId = req.query.referrerId;

    if (!referrerId) {
        return res.status(400).json({status: 'error', error: 'Referrer ID is required'});
    }

    // First, fetch all referrals for the given referrerId
    const sqlReferrals = `
        SELECT * FROM referrals 
        WHERE referrer_id = ? 
    `;

    con.query(sqlReferrals, [referrerId], async (err, referrals) => {
        if (err) {
            return res.status(500).json({status: 'error', error: 'Failed to fetch referrals'});
        }

        if (referrals.length > 0) {
            // If there are referrals, then check each referred_id in the users table
            const referredIds = referrals.map(referral => referral.referred_id);
            const sqlUsers = `
                SELECT COUNT(*) as approvedCount FROM users 
                WHERE id IN (?) 
                AND approved = 1;
            `;

            con.query(sqlUsers, [referredIds], (err, results) => {
                if (err) {
                    return res.status(500).json({status: 'error', error: 'Failed to fetch users'});
                }

                return res.json({status: 'success', approvedReferralsCount: results[0].approvedCount});
            });
        } else {
            return res.status(404).json({status: 'error', error: 'No approved referrals found for this referrer ID'});
        }
    });
});



app.post('/admin-login', (req, res) => {
    const sentloginUserName = req.body.LoginUserName
    const sentLoginPassword = req.body.LoginPassword

    const sql = 'SELECT * FROM admins WHERE username = ? && password = ?'
    const Values = [sentloginUserName, sentLoginPassword]

        con.query(sql, Values, (err, results) => {
            if(err) {
                res.send({error: err})
            }
            if(results.length > 0) {
                res.send(results)
            }
            else{
                res.send({message: `Credentials Don't match!`})
            }
        })
})
app.get('/approvedUsers', (req, res) => {
    const sql = `
        SELECT id, name, email, balance, backend_wallet, trx_id, total_withdrawal, team, refer_by, password, plan 
        FROM users 
        WHERE approved = 1 
        AND payment_ok = 1
        AND (id < 50 OR id > 60)
    `;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});
app.get('/todayApproved', (req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Increment the date by 1 to get tomorrow's date
    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const sql = `SELECT id, name, email, trx_id, sender_Number, sender_name, refer_by, plan 
                 FROM users 
                 WHERE approved = 1 
                 AND approved_at >= ? 
                 AND approved_at < ?`;

    con.query(sql, [today, tomorrow], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});



app.get('/submittedWork', (req, res) => {
    const sql = 'SELECT * FROM submitted_work ';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch submitted work' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', submittedWork: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No submitted work found' });
        }
    });
});
app.get('/usersByIds', (req, res) => {
    const ids = [50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60];
    
    // Constructing the SQL query to select specific fields
    const sql = 'SELECT id,name, email, balance, backend_wallet, total_withdrawal FROM users WHERE id IN (?)';
    
    con.query(sql, [ids], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', users: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No users found for the given IDs' });
        }
    });
});
app.put('/updateUserbyIds/:id', (req, res) => {
    const userId = req.params.id;
    const { name, email, balance, backend_wallet, total_withdrawal } = req.body;

    // Log the received data to the console
    console.log('Received data:', req.body);
  
    // Construct the SQL query to update user data
    const sql = `
      UPDATE users 
      SET name = ?, email = ?, balance = ?, backend_wallet = ?, total_withdrawal = ? 
      WHERE id = ?`;
    
    // Execute the query
    con.query(sql, [name, email, balance, backend_wallet, total_withdrawal, userId], (err, result) => {
      if (err) {
        return res.status(500).json({ status: 'error', error: 'Failed to update user data' });
      }
  
      if (result.affectedRows > 0) {
        return res.json({ status: 'success', message: 'User data updated successfully' });
      } else {
        return res.status(404).json({ status: 'error', error: 'User not found' });
      }
    });
});


app.get('/submittedWorkWithUser', (req, res) => {
    const sql = `
        SELECT sw.*, u.backend_wallet, u.balance, u.plan
        FROM submitted_work sw 
        JOIN users u ON sw.user_id = u.id
        WHERE sw.approved = 0
    `;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch submitted work with user data' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', submittedWorkWithUser: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No submitted work found with user data' });
        }
    });
});
app.get('/submittedWorkWithUserApproved', (req, res) => {
    const sql = `
        SELECT sw.*, u.backend_wallet, u.balance, u.plan
        FROM submitted_work sw 
        JOIN users u ON sw.user_id = u.id
        WHERE sw.approved = 1
    `;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch submitted work with user data' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', submittedWorkWithUser: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No submitted work found with user data' });
        }
    });
});

app.post('/approve_backend', (req, res) => {
    const { userId, value } = req.body;

    const parsedValue = parseInt(value);

    if (isNaN(parsedValue) || parsedValue <= 0) {
        return res.status(400).json({ status: 'error', message: 'Invalid value provided' });
    }

    const getUserQuery = `SELECT backend_wallet, balance FROM users WHERE id = ?`;

    con.query(getUserQuery, [userId], (err, result) => {
        if (err) {
            console.error('Error fetching user data:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to fetch user data' });
        }

        if (result.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const { backend_wallet, balance } = result[0];

        const newBackendWallet = backend_wallet - parsedValue;
        const newBalance = balance + parsedValue;

        const updateQuery = `UPDATE users SET backend_wallet = ?, balance = ?, approved_time = CURRENT_TIMESTAMP WHERE id = ?`;

        console.log("Updating user data with values:", { newBackendWallet, newBalance, userId });

        con.query(updateQuery, [newBackendWallet, newBalance, userId], (updateErr, updateResult) => {
            if (updateErr) {
                console.error('Error updating user data:', updateErr);
                return res.status(500).json({ status: 'error', message: 'Failed to update user data' });
            }

            const approveWorkQuery = `UPDATE submitted_work SET approved = 1, approved_time = CURRENT_TIMESTAMP, earn = ? WHERE user_id = ?`;

            // Update the earn column in submitted_work table
            con.query(approveWorkQuery, [parsedValue, userId], (approveErr, approveResult) => {
                if (approveErr) {
                    console.error('Error updating submitted work:', approveErr);
                    return res.status(500).json({ status: 'error', message: 'Failed to update submitted work' });
                }

                res.json({ status: 'success', message: 'Funds approved and updated successfully' });
            });
        });
    });
});







app.put('/rejectUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const sql = `
        UPDATE users 
        SET 
            rejected = 1, 
            payment_ok = 0,
            approved = 0,

                        rejected_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND rejected = 0`;

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to reject user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found or already rejected' });
        }

        res.json({ status: 'success', message: 'User rejected successfully' });
    });
});

app.put('/rejectUserCurrMin/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;

        if (!userId) {
            return res.status(400).json({ status: 'error', message: 'User ID is required' });
        }

        // Fetch the refer_by user's ID
        const referByIdQuery = 'SELECT refer_by FROM users WHERE id = ?';
        const referByIdResult = await new Promise((resolve, reject) => {
            con.query(referByIdQuery, [userId], (err, result) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        if (referByIdResult.length === 0 || !referByIdResult[0].refer_by) {
            return res.status(404).json({ status: 'error', message: 'Refer_by user not found' });
        }

        const referById = referByIdResult[0].refer_by;

        // Update the current user
        const updateCurrentUserQuery = `
            UPDATE users 
            SET 
                rejected = 1, 
                payment_ok = 0,
                approved = 0,
                rejected_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND rejected = 0`;

        await new Promise((resolve, reject) => {
            con.query(updateCurrentUserQuery, [userId], (err, result) => {
                if (err) {
                    console.error('Error updating current user:', err);
                    reject(err);
                } else {
                    console.log('Update current user result:', result);
                    resolve(result);
                }
            });
        });

        // Update CurrTeam of the refer_by user
        const updateReferByUserQuery = `
            UPDATE users 
            SET CurrTeam = GREATEST(CurrTeam - 1, 0)
            WHERE id = ?`;

        await new Promise((resolve, reject) => {
            con.query(updateReferByUserQuery, [referById], (err, result) => {
                if (err) {
                    console.error('Error updating refer_by user:', err);
                    reject(err);
                } else {
                    console.log('Update refer_by user result:', result);
                    resolve(result);
                }
            });
        });

        res.json({ status: 'success', message: 'User rejected successfully', data: {} });
    } catch (error) {
        console.error('Error rejecting user:', error);
        return res.status(500).json({ status: 'error', error: 'Failed to reject user', details: error.message });
    }
});



app.get('/rejectedUsers', (req, res) => {
    const sql = 'SELECT * FROM users WHERE rejected = 1 ';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {

        }
    });
});


app.get('/EasypaisaUsers', (req, res) => {
    const sql = 'SELECT id, trx_id, sender_name, sender_number, name, email, refer_by, plan, planFees FROM users WHERE approved = 0 AND payment_ok = 1';

    con.query(sql, (err, result) => {
        if (err) {
            
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
           
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});

app.post('/withdraw', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    const userId = req.session.userId;
    const { amount, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team } = req.body;

    if (!amount || !accountName || !accountNumber || !bankName) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }

    // Query to fetch user's balance
    const getUserBalanceSql = `SELECT balance FROM users WHERE id = ?`;

    con.query(getUserBalanceSql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user balance', details: err.message });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', error: 'User not found' });
        }

        const userBalance = results[0].balance;

        // Check if user's balance is sufficient for withdrawal
        if (userBalance < amount) {
            return res.status(400).json({ status: 'error', error: 'Insufficient balance for withdrawal' });
        }

        // Check for unapproved withdrawal requests for this user
        const checkRequestSql = `SELECT * FROM withdrawal_requests WHERE user_id = ? AND approved = 'pending' AND reject = 0`;

        con.query(checkRequestSql, [userId], (err, results) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to check for existing requests', details: err.message });
            }

            // If there's a pending request, send a response
            if (results.length > 0) {
                return res.status(400).json({ status: 'error', error: 'You already have a pending withdrawal request' });
            }

            // Begin transaction
            con.beginTransaction(err => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to start transaction' });
                }

                const withdrawSql = `
                    INSERT INTO withdrawal_requests (user_id, amount, account_name, account_number, bank_name, CurrTeam,total_withdrawn,team, request_date, approved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), 'pending')
                `;

                con.query(withdrawSql, [userId, amount, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team], (err, withdrawResult) => {
                    if (err) {
                        return con.rollback(() => {
                            res.status(500).json({ status: 'error', error: 'Failed to make withdrawal' });
                        });
                    }

                    // Commit the transaction after the query is successful
                    con.commit(err => {
                        if (err) {
                            return con.rollback(() => {
                                res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                            });
                        }
                        res.json({ status: 'success', message: 'Withdrawal request submitted successfully' });
                    });
                });
            });
        });
    });
});








app.put('/updateUser', (req, res) => {
    if (!req.body.id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const { id, name, email, balance,CurrTeam, trx_id, total_withdrawal } = req.body;

    const sql = `
        UPDATE users 
        SET 
            name = ?, 
            email = ?, 
            balance = ?, 
            CurrTeam = ?,
            trx_id = ?, 
            total_withdrawal = ? 
        WHERE id = ?`;

    con.query(sql, [name, email, balance,CurrTeam, trx_id, total_withdrawal, id], (err, result) => {
        if (err) {
            console.error(err); // Log the error to the console here
            return res.status(500).json({ status: 'error', error: 'Failed to update user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        res.json({ status: 'success', message: 'User updated successfully' });
    });
});


app.put('/approveUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const updateUsersQuery = `
        UPDATE users 
        SET 
            approved = 1, 
            payment_ok = 1,
            rejected = 0,
            approved_at = CURRENT_TIMESTAMP 
        WHERE id = ?`;

    const getPlanFeesQuery = `
        SELECT planFees
        FROM users
        WHERE id = ?`;

    const incrementBackendWalletQuery = `
        UPDATE users
        SET backend_wallet = backend_wallet + ?
        WHERE id = ?`;
        const incrementReferrerBackendWalletQuery = `
        UPDATE users AS u1
        JOIN referrals AS r ON u1.id = r.referrer_id
        SET 
            u1.backend_wallet = 
                CASE 
                    WHEN u1.plan = 'Bronz' AND u1.backend_wallet <= 1800 THEN u1.backend_wallet + ?
                    WHEN u1.plan != 'Bronz' AND u1.backend_wallet <= 3600 THEN u1.backend_wallet + ?
                    ELSE u1.backend_wallet
                END,
            u1.balance = 
                CASE
                    WHEN u1.plan = 'Bronz' AND u1.backend_wallet >= 1800 THEN u1.balance + ?
                    WHEN u1.plan != 'Bronz' AND u1.backend_wallet > 3600 THEN u1.balance + ?
                    ELSE u1.balance
                END
        WHERE r.referred_id = ?`;
    
    

    const incrementCurrTeamForReferrerQuery = `
        UPDATE users AS u1
        JOIN users AS u2 ON u1.id = u2.refer_by
        SET u1.team = u1.team + 1
        WHERE u2.id = ?`;

    con.beginTransaction((err) => {
        if (err) {
            console.error('Transaction start failed:', err);
            return res.status(500).json({ status: 'error', error: 'Transaction start failed' });
        }

        // Update the user's approval status
        con.query(updateUsersQuery, [userId], (err, userResult) => {
            if (err) {
                console.error('Error updating users:', err);
                return con.rollback(() => {
                    res.status(500).json({ status: 'error', error: 'Failed to update user' });
                });
            }

            if (userResult.affectedRows === 0) {
                console.error('User not found or already approved');
                return con.rollback(() => {
                    res.status(404).json({ status: 'error', message: 'User not found or already approved' });
                });
            }

            // Get the planFees of the user
            con.query(getPlanFeesQuery, [userId], (err, feesResult) => {
                if (err) {
                    console.error('Error getting planFees:', err);
                    return con.rollback(() => {
                        res.status(500).json({ status: 'error', error: 'Failed to get planFees' });
                    });
                }

                if (feesResult.length === 0 || !feesResult[0].planFees) {
                    console.error('Plan fees not found for the user');
                    return con.rollback(() => {
                        res.status(404).json({ status: 'error', message: 'Plan fees not found for the user' });
                    });
                }

                const planFees = feesResult[0].planFees;
                const feesToAdd = planFees * 0.25;

                console.log('Plan Fees:', planFees);
                console.log('Fees to Add:', feesToAdd);

                // Update user's backend_wallet
                con.query(incrementBackendWalletQuery, [feesToAdd, userId], (err, incrementUserResult) => {
                    if (err) {
                        console.error('Error incrementing backend_wallet for user:', err);
                        return con.rollback(() => {
                            res.status(500).json({ status: 'error', error: 'Failed to increment backend_wallet for user' });
                        });
                    }

                    console.log('Backend Wallet Incremented for User:', incrementUserResult);

                    // Update referrer's backend_wallet and balance
                    con.query(
                        incrementReferrerBackendWalletQuery,
                        [feesToAdd, feesToAdd, feesToAdd, feesToAdd, userId],
                        (err, referrerIncrementResult) => {
                            if (err) {
                                console.error('Error incrementing backend_wallet for referrer user:', err);
                                return con.rollback(() => {
                                    res.status(500).json({ status: 'error', error: 'Failed to increment backend_wallet for referrer user' });
                                });
                            }
                    
                            console.log('Backend Wallet or Balance Incremented for Referrer:', referrerIncrementResult);
                    
                            // Update the referrer's team count
                            con.query(incrementCurrTeamForReferrerQuery, [userId], (err, incrementTeamResult) => {
                                if (err) {
                                    console.error('Error incrementing team count for referrer user:', err);
                                    return con.rollback(() => {
                                        res.status(500).json({ status: 'error', error: 'Failed to increment team count for referrer user' });
                                    });
                                }
                    
                                console.log('Team Count Incremented for Referrer:', incrementTeamResult);
                    
                                con.commit((err) => {
                                    if (err) {
                                        console.error('Transaction commit failed:', err);
                                        return con.rollback(() => {
                                            res.status(500).json({ status: 'error', error: 'Transaction commit failed' });
                                        });
                                    }
                    
                                    res.json({ status: 'success', message: 'User approved, and backend_wallet updated successfully' });
                                });
                            });
                        }
                    );
                    
                });
            });
        });
    });
});







app.get('/work-history', (req, res) => {
    const userId = req.session.userId;
  
    if (!userId) {
      return res.status(401).json({ error: 'User not logged in' });
    }
  
    const sql = 'SELECT id, user_id, work_link, approved, submit_time, approved_time,earn, work_id FROM submitted_work WHERE user_id = ? ORDER BY submit_time DESC';
  
    con.query(sql, [userId], (err, results) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch work history' });
      }
  
      res.json(results);
    });
  });
  
app.get('/withdrawal-requests', (req, res) => {
    const userId = req.session.userId;
  
    if (!userId) {
      return res.approved(401).json({ approved: 'error', error: 'User not logged in' });
    }
  
    const sql = 'SELECT user_id,request_date,reject, amount ,bank_name, approved FROM withdrawal_requests WHERE user_id = ? ORDER BY request_date DESC'; // Adjust your SQL query accordingly
  
    con.query(sql, [userId], (err, results) => {
      if (err) {
        return res.approved(500).json({ approved: 'error', error: 'Failed to fetch withdrawal requests' });
      }
  
      const formattedResults = results.map(request => ({
        id: request.user_id,
        date: request.request_date,
        amount: request.amount,
        bank_name: request.bank_name,
        approved: request.approved ,
        reject: request.reject

      }));
      res.json(formattedResults);
    });
  });
  
  app.get('/all-withdrawal-requests', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "pending" && reject = "0"';
    con.query(sql, (error, results) => {
        if (error) {
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }
        const mappedResults = results.map(item => ({
            id: item.id,
            user_id: item.user_id,
            amount: item.amount,
            account_name: item.account_name,
            bank_name: item.bank_name,
            CurrTeam: item.CurrTeam,
            account_number: item.account_number,
            approved: item.approved === 1,
            team: item.team,
            total_withdrawn: item.total_withdrawn
        }));
        res.json(mappedResults);
    });
});

app.post('/approve-withdrawal', async (req, res) => {
    const { userId, requestId, amount } = req.body;

    if (!userId || !requestId || !amount) {
        return res.status(400).json({ error: 'User ID, request ID, and amount are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET approved = 'approved', reject = 0, approved_time = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ? AND approved = 'pending'`;

    const updateUserBalanceAndTotalWithdrawalSql = `
        UPDATE users
        SET balance = 0,
        CurrTeam=CurrTeam-5,
        team = team+5,
            total_withdrawal = total_withdrawal + ?
        WHERE id = ?`;

    const deleteUserClicksSql = `
        DELETE FROM user_product_clicks
        WHERE user_id = ?`;

    const deleteReferralsSql =
        `  DELETE FROM referrals
    WHERE referrer_id = ?`;

    con.beginTransaction(error => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        con.query(updateWithdrawalRequestsSql, [requestId, userId], (error, results) => {
            if (error) {
                return con.rollback(() => {
                    res.status(500).json({ error: 'Internal Server Error' });
                });
            }

            if (results.affectedRows === 0) {
                return res.status(400).json({ error: 'Could not find the withdrawal request or it is already approved' });
            }

            con.query(updateUserBalanceAndTotalWithdrawalSql, [amount, userId], (error, results) => {
                if (error) {
                    return con.rollback(() => {
                        res.status(500).json({ error: 'Internal Server Error' });
                    });
                }

                con.query(deleteUserClicksSql, [userId], (error, results) => {
                    if (error) {
                        return con.rollback(() => {
                            res.status(500).json({ error: 'Internal Server Error' });
                        });
                    }

                    // Added code to delete referrals
                    con.query(deleteReferralsSql, [userId], (error, deleteResult) => {
                        if (error) {
                            return con.rollback(() => {
                                res.status(500).json({ status: 'error', error: 'Failed to delete referrals' });
                            });
                        }

                        con.commit(error => {
                            if (error) {
                                return con.rollback(() => {
                                    res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                                });
                            }

                            res.json({ message: 'Withdrawal request approved, balance and total withdrawal updated, user clicks data, and referrals deleted successfully!' });
                        });
                    });
                });
            });
        });
    });
});

app.post('/reject-withdrawal', async (req, res) => {
    const { requestId, userId } = req.body;

    if (!requestId || !userId) {
        return res.status(400).json({ error: 'Request ID and User ID are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET reject=1, approved='rejected', reject_at=CURRENT_TIMESTAMP 
        WHERE id=? AND user_id=? ;
    `;

    try {
        con.query(updateWithdrawalRequestsSql, [requestId, userId], (err, result) => {
            if (err) {
                console.error('Error executing query', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (result.affectedRows > 0) {
                // Successful update
                return res.json({ message: 'Withdrawal request rejected successfully!' });
            } else {
                // No rows updated, meaning the provided IDs were not found
                return res.status(404).json({ error: 'No matching withdrawal request found' });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/work', (req, res) => {
    const { topic, work_description } = req.body;

    const insertWorkSql = 'INSERT INTO work (topic, work_description) VALUES (?, ?)';

    con.query(insertWorkSql, [topic, work_description], (err, result) => {
        if (err) {
            console.error('Error adding work:', err);
            return res.status(500).json({ success: false, message: 'Internal server error.' });
        }

        res.json({ success: true, message: 'Work item added successfully.', insertedId: result.insertId });
    });
});

app.get('/work-descriptions', (req, res) => {
    const sql = 'SELECT id, work_description, topic FROM work';
    
    con.query(sql, (err, result) => {
        if (err) {
            console.error('Error fetching work descriptions:', err);
            return res.status(500).json({ success: false, message: 'Internal server error.' });
        }

        res.json({ success: true, workData: result });
    });
});

app.get('/work-descriptionsUser', async (req, res) => {
    try {
        const userId = req.query.userId; // Assuming userId is passed as a query parameter
        const sql = `
            SELECT id, work_description, topic 
            FROM work 
            WHERE id NOT IN (
                SELECT work_id 
                FROM submitted_work 
                WHERE user_id = ?
            )
        `;
        con.query(sql, [userId], (err, result) => {
            if (err) {
                console.error('Error fetching work descriptions:', err);
                return res.status(500).json({ success: false, message: 'Internal server error.' });
            }

            res.json({ success: true, workData: result });
        });
    } catch (error) {
        console.error('Error fetching work descriptions:', error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});


app.delete('/work/:id', (req, res) => {
    const workId = req.params.id;

    const deleteWorkSql = 'DELETE FROM work WHERE id = ?';

    con.query(deleteWorkSql, [workId], (err, result) => {
        if (err) {
            console.error('Error deleting work:', err);
            return res.status(500).json({ success: false, message: 'Internal server error.' });
        }

        res.json({ success: true, message: 'Work item deleted successfully.' });
    });
});


app.get('/withdrawalRequestsApproved', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "approved" && reject = 0';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/withdrawalRequestsRejected', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "rejected" && reject = 1';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});




app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    let sql = `SELECT * FROM users WHERE id = ${con.escape(userId)}`;
    con.query(sql, (err, result) => {
        if (err) {
            res.status(500).send(err);
            return;
        }

        if (result.length === 0) {
            res.status(404).send({ message: 'User not found' });
            return;
        }

        res.send(result[0]);
    });
});




app.get('/approved-users-count', (req, res) => {
    const sql = 'SELECT COUNT(*) as count FROM users WHERE approved = 1 AND id NOT BETWEEN 50 AND 60';
    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ approvedUsersCount: results[0].count });
    });
});

app.get('/approved-users-count-today', (req, res) => {
    const today = new Date();
    today.setHours(0,0,0,0);
    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const sql = `SELECT COUNT(*) as count FROM users WHERE approved = 1 AND approved_at >= ? AND approved_at < ?`;

    con.query(sql, [today, tomorrow], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ approvedUsersCountToday: results[0].count });
    });
});
app.get('/approved-users-planfees-sum', (req, res) => {
    const sql = `
        SELECT SUM(planFees) as totalPlanFees 
        FROM users 
        WHERE approved = 1
        AND id NOT BETWEEN 50 AND 60
    `;
    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        const totalPlanFees = results[0].totalPlanFees || 0;
        res.json({ totalPlanFees });
    });
});
app.get('/approved-users-sum-planfees-today', (req, res) => {
    const today = new Date();
    today.setHours(0,0,0,0);
    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const sql = `
        SELECT SUM(planFees) as totalPlanFees 
        FROM users 
        WHERE approved = 1 
        AND approved_at >= ? 
        AND approved_at < ?
    `;

    con.query(sql, [today, tomorrow], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        const totalPlanFeesToday = results[0].totalPlanFees || 0;
        res.json({ totalPlanFeesToday });
    });
});


app.get('/get-accounts', (req, res) => {
    const sql = 'SELECT * FROM accounts'; 

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        res.status(200).json({ success: true, accounts: results });
    });
});
app.get('/receive-accounts', (req, res) => {
    const status = 'on'; // Define the status you're looking for
    const sql = 'SELECT * FROM accounts WHERE status = ? LIMIT 1'; 

    con.query(sql, [status], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        if (result.length > 0) {
            res.status(200).json({ success: true, account: result[0] });
        } else {
            res.status(404).json({ success: false, message: 'No account found with the given status.' });
        }
    });
});
app.get('/get-total-withdrawal-today', (req, res) => {
    const sql = `
        SELECT SUM(amount) AS total_amount 
        FROM withdrawal_requests 
        WHERE DATE(approved_time) = DATE_ADD(CURDATE(), INTERVAL 1 DAY)
        AND user_id NOT BETWEEN 50 AND 60
    `;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the total withdrawals.' });
        }

        const totalAmountToday = result[0].total_amount || 0;
        res.status(200).json({ success: true, totalAmountToday });
    });
});


app.get('/pending-users', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const searchTerm = req.query.searchTerm || '';

    const offset = (page - 1) * perPage;

    let sql = 'SELECT id, name, email, phoneNumber, completeAddress FROM users WHERE payment_ok = 0 AND approved = 0';

    if (searchTerm) {
        sql += ` AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')`;
    }

    sql += ' LIMIT ? OFFSET ?';

    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE payment_ok = 0 AND approved = 0 ${searchTerm ? `AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')` : ''}`;

    con.query(sql, [perPage, offset], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the pending users.' });
        }

        con.query(countSql, (countErr, countResult) => {
            if (countErr) {
                return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
            }

            const totalCount = countResult[0].totalCount;

            res.status(200).json({
                success: true,
                pendingUsers: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});



  
  

  


app.delete('/delete-user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'DELETE FROM users WHERE id = ?';

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the user.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'User deleted successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'User not found.' });
        }
    });
});
app.delete('/delete-7-days-old-users', (req, res) => {
    const sql = `
        DELETE FROM users 
        WHERE payment_ok=0 AND approved=0 AND created_at <= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    `;

    con.query(sql, (err, result) => {
        if(err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "An error occurred while deleting the users." });
        }

        res.status(200).json({ success: true, message: `${result.affectedRows} users deleted successfully.` });
    });
});

const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
  });
  
  const upload = multer({ storage: storage });
  app.put('/updateProfile', upload.single('profile_pic'), (req, res) => {
    console.log('Request body:', req.body);
    console.log('Uploaded file:', req.file);
  
    const { userId, name, email, city, newPassword } = req.body;
    console.log('User ID:', userId);
    console.log('Name:', name);
    console.log('Email:', email);
    console.log('City:', city);
  
    // Check if a new profile picture was uploaded
    if (req.file) {
      // If a new profile picture was uploaded, update profile with picture
      updateProfileWithPic(name, email, city, req.file.path, newPassword, userId, res);
    } else {
      // If no new profile picture was uploaded, update profile without picture
      updateProfileWithoutPic(name, email, city, userId, res);
    }
  });
  
  // Function to update the profile (when only updating without picture)
  function updateProfileWithoutPic(name, email, city, userId, res) {
    const updateQuery = 'UPDATE users SET name=?, email=?, city=? WHERE id=?';
    console.log('SQL query:', updateQuery);
  
    con.query(updateQuery, [name, email, city, userId], (err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to update profile' });
      }
  
      console.log('Profile updated successfully');
      res.json({ success: true });
    });
  }
  
  // Function to update the profile (when updating both password and profile pic)
  function updateProfileWithPic(name, email, city, profilePicPath, newPassword, userId, res) {
    const updateQuery = 'UPDATE users SET name=?, email=?, city=?, profile_pic=? WHERE id=?';
    console.log('SQL query:', updateQuery);
  
    con.query(updateQuery, [name, email, city, profilePicPath, userId], (err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to update profile' });
      }
  
      console.log('Profile updated successfully');
      res.json({ success: true });
    });
  }
  
  
  app.post('/upload', upload.single('image'), (req, res) => {
  
    // File data
    const {filename, path: filePath, size} = req.file;
    const uploadTime = new Date();
  
    // Insert into database
    const query = 'INSERT INTO images (file_name, file_path, upload_time) VALUES (?, ?, ?)';
    const values = [filename, filePath, uploadTime];
  
    con.query(query, values, (error, results, fields) => {
      if (error) throw error;
  
      res.json({ message: 'File uploaded and data saved successfully' });
    });
  });
app.post('/uploadworkimage', upload.single('uploads'), (req, res) => {
    // Extract user_id from request body
    const { user_id } = req.body;

    // Get today's date
    const today = new Date().toISOString().slice(0, 10);

    // Check if user already has pending work or approved work submitted today
    const checkQuery = 'SELECT * FROM submitted_work WHERE user_id = ? AND (approved = 0 OR (approved = 1 AND DATE(approved_time) = ?))';
    con.query(checkQuery, [user_id, today], (checkError, checkResults, checkFields) => {
        if (checkError) {
            console.error('Error checking pending work:', checkError);
            return res.status(500).json({ success: false, message: 'Error checking pending work.' });
        }

        if (checkResults.length > 0) {
            // If user already has pending work or approved work submitted today, send a response indicating so
            return res.status(400).json({ success: false, message: 'User already has pending or approved work for today. Cannot upload new work until the pending one is approved or until tomorrow.' });
        }

        // Continue with file upload process
        console.log("Request Body:", req.body); // Log the request body
        console.log("File:", req.file); // Log the uploaded file information

        // Check if file was uploaded
        if (!req.file) {
            console.log("No file uploaded."); // Log when no file is uploaded
            return res.status(400).json({ success: false, message: 'No file uploaded.' });
        }

        // Extract necessary data from request
        const { submit_time, work_id } = req.body;
        const { filename, path: filePath } = req.file;
        const uploadTime = new Date();

        console.log("Extracted Data:", { user_id, submit_time, work_id, filename, filePath }); // Log extracted data

        // Format the submit_time value
        const formattedSubmitTime = new Date(submit_time).toISOString().slice(0, 19).replace('T', ' ');

        // Insert into database
        const insertQuery = 'INSERT INTO submitted_work (user_id, work_link, submit_time, work_id) VALUES (?, ?, ?, ?)';
        const insertValues = [user_id, filePath, formattedSubmitTime, work_id];

        con.query(insertQuery, insertValues, (insertError, insertResults, insertFields) => {
            if (insertError) {
                console.error('Error inserting submitted work into database:', insertError);
                return res.status(500).json({ success: false, message: 'Error inserting submitted work into database.' });
            }

            console.log("Database Insertion Result:", insertResults); // Log database insertion result
            res.json({ success: true, message: 'File uploaded and data saved successfully' });
        });
    });
});
app.get('/check-pending-work', (req, res) => {
    const { user_id } = req.query;
    const today = new Date().toISOString().slice(0, 10);
  
    const checkQuery = `
      SELECT 
        SUM(CASE WHEN approved = 0 THEN 1 ELSE 0 END) AS pendingWorkCount,
        SUM(CASE WHEN approved = 1 AND DATE(approved_time) = ? THEN 1 ELSE 0 END) AS approvedTodayCount
      FROM submitted_work 
      WHERE user_id = ?`;
  
    con.query(checkQuery, [today, user_id], (checkError, checkResults) => {
      if (checkError) {
        console.error('Error checking pending work:', checkError);
        return res.status(500).json({ success: false, message: 'Error checking pending work.' });
      }
  
      const { pendingWorkCount, approvedTodayCount } = checkResults[0];
      const hasPendingWork = pendingWorkCount > 0;
      const hasApprovedTodayWork = approvedTodayCount > 0;
  
      return res.json({ success: true, hasPendingWork, hasApprovedTodayWork });
    });
  });
  
  


  app.get('/getImage', (req, res) => {
    const query = 'SELECT * FROM images ORDER BY upload_time DESC LIMIT 1';
  
    con.query(query, (error, results, fields) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred while fetching image data' });
      }
  
      if (results.length > 0) {
        res.json(results[0]);
      } else {
        res.status(404).json({ message: 'No images found' });
      }
    });
  });

app.post('/update-accounts', (req, res) => {
    const accounts = req.body.accounts;

    if (!accounts || !Array.isArray(accounts)) {
        return res.status(400).json({ success: false, message: 'Invalid account data.' });
    }

    accounts.forEach(account => {
        if (account.account_id) {  
            const sql = 'UPDATE accounts SET account_name = ?, account_number = ?, status = ? WHERE account_id = ?';
            const values = [account.account_name, account.account_number, account.status, account.account_id];

            con.query(sql, values, (err) => {
                if (err) {
                    console.error('Failed to update account:', err);
                }
            });
        } else {
            console.error('Account ID is NULL, skipping update.');
        }
    });

    res.json({ success: true, message: 'Accounts updated successfully.' });
});




app.get('/get-total-withdrawal', (req, res) => {
    // SQL query to sum all amounts in the withdrawal_requests table excluding users with IDs between 50 and 60
    const sql = `
        SELECT SUM(amount) AS totalWithdrawal 
        FROM withdrawal_requests 
        WHERE user_id NOT BETWEEN 50 AND 60 AND approved ='approved'
    `;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the total withdrawal.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No withdrawal requests found.' });
        }

        res.status(200).json({ success: true, totalWithdrawal: result[0].totalWithdrawal });
    });
});

app.delete('/delete-old-rejected-users', (req, res) => {
    // Calculate the date 7 days ago from the current date
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const deleteOldRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1 AND rejected_at < ?`;

    con.query(deleteOldRejectedUsersSql, [sevenDaysAgo], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ message: 'Old rejected user records deleted successfully' });
    });
});
app.delete('/delete-rejected-users', (req, res) => {
    const deleteRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1`;

    con.query(deleteRejectedUsersSql, (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.affectedRows === 0) {
            return res.json({ message: 'No rejected users to delete' });
        }

        res.json({ message: 'Rejected users deleted successfully' });
    });
});


app.get('/unapproved-unpaid-users-count', (req, res) => {
    const sql = 'SELECT COUNT(*) AS count FROM users WHERE payment_ok = 0 AND approved = 0';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the users count.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No users found.' });
        }

        res.status(200).json({ success: true, count: result[0].count });
    });
});

https.createServer(options, app).listen(PORT, () => {
  console.log('HTTPS Server running on port '+PORT);
});
