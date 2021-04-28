const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongodb = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require("dotenv");

/*
  Funkcja generująca token o ważności na czas jednej godziny.
*/
function generateAccessToken(username) {
  return jwt.sign(username, process.env.TOKEN_SECRET, { expiresIn: '3600s' });
}

dotenv.config();

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const PORT = process.env.PORT || 5000;
const DB_URL = process.env.DATABASE_URL;

app.listen(PORT);

app.get('/weather/', (req, res) => {

  jwt.verify(req.headers.authorization, process.env.TOKEN_SECRET, (err, decode) => {

    /*
      Sprawdzamy poprawność tokena.
    */
    if (err) {
      res.status(404).send({message: 'Błąd autoryzacji.'});
      return;
    }

    mongodb.MongoClient.connect(DB_URL, { useUnifiedTopology: true }, (err, client) => {

      if (err) {
        res.status(404).send({message: 'Błąd połączenia z MongoDB.'});
        return;
      }

      const db = client.db('db_weather');
      db.collection('weather').find().toArray((err, result) => {
        if (err) return console.log(err);
        res.send(JSON.stringify(result));
      });
  
    });
  });

});

app.post('/weather/', (req, res) => {

  jwt.verify(req.headers.authorization, process.env.TOKEN_SECRET, (err, decode) => {

    /*
      Sprawdzamy poprawność tokena.
    */
    if (err) {
      res.status(404).send({message: 'Błąd autoryzacji.'});
      return;
    }

    mongodb.MongoClient.connect(DB_URL, { useUnifiedTopology: true }, (err, client) => {

      if (err) {
        res.status(404).send({message: 'Błąd połączenia z MongoDB.'});
        return;
      }
      
      const db = client.db('db_weather');
      db.collection('weather').insertMany(req.body).catch(err => console.log(err));
      res.status(200).send({message: "Dodano do bazy danych!"});

    });
  });

});

app.delete('/weather/:id', (req, res) => {

  jwt.verify(req.headers.authorization, process.env.TOKEN_SECRET, (err, decode) => {

    /*
      Sprawdzamy poprawność tokena.
    */
    if (err) {
      res.status(404).send({message: 'Błąd autoryzacji.'});
      return;
    }

    mongodb.MongoClient.connect(DB_URL, { useUnifiedTopology: true }, (err, client) => {

      if (err) {
        res.status(404).send({message: 'Błąd połączenia z MongoDB.'});
        return;
      }

      const db = client.db('db_weather');
      const [place, date] = req.params.id.split('_');
      db.collection('weather').deleteMany({place: place, date: date})
      .then(res.status(200).send({message: "Usunięto z bazy danych!"}))
      .catch(err => res.status(400).send({message: "Błąd podczas usuwania"}));
    });
  }); 

})

app.post('/register/', (req, res) => {

  mongodb.MongoClient.connect(DB_URL, { useUnifiedTopology: true }, async (err, client) => {

    if (err) {
      res.status(404).send({message: 'Błąd połączenia z MongoDB.'});
      return;
    }

    const db = client.db('db_users');
    db.collection('users').findOne({username: req.body.username})
    .then(async user => {

      /*
        Sprawdzamy czy już istnieje użytkownik o tej nazwie.
      */
      if (user == null) {

        /*
          Hashujemy hasło.
        */
        try {
          const hashedPassword = await bcrypt.hash(req.body.password, 10);
          const user = {
            username: req.body.username,
            password: hashedPassword
          };
          db.collection('users').insertOne(user, (err, result) => {
            if (err) {
              res.status(404).send({message: 'Błąd połączenia rejestracji.'});
              return;
            }
            res.status(200).send({
              message: "Poprawnie zarejestrowano użytkownika"
            });
          });
        } catch (error) {
          res.status(500).send({message: error});
        }

      } else {
        res.status(400).send({
          message: "Użytkownik o podanej nazwie jest już w zarejestrowany w bazie"
        });
      }
    });

  });
});

app.post('/login/', (req, res) => {

  mongodb.MongoClient.connect(DB_URL, { 
    useUnifiedTopology: true 
  }, (err, client) => {

    if (err) {
      res.status(404).send({message: 'Błąd połączenia z MongoDB.'});
      return;
    }

    const db = client.db('db_users');
    db.collection('users').findOne({username: req.body.username})
    .then(async user => {

      /*
        Sprawdzamy czy podana nazwa użytkownika istnieje.
      */
      if (user == null) {
        res.status(400).send({message: 'No such user'});
        return;
      }
      try {
        /*
          Porównujemy podane hasło z tym w bazie.
        */
        if (await bcrypt.compare(req.body.password, user.password)) {
          const token = generateAccessToken({ username: req.body.username} );
          res.status(200).send(JSON.stringify({
            message: "Zalogowano użytkownika", 
            token: token
          }));
        } else {
          res.status(400).send({message: 'Zły login lub hasło.'});
        }
      } catch {
        res.status(500).send({message: "Błąd"});
      }
    })
    .catch(err => {
      res.status(500).send({message: "Błąd"});
    });

  });

});
