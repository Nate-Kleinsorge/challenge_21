const express = require('express');
const path = require('path');
const db = require('./config/connection');
const { ApolloServer } = require('./apollo-server-express');

const { typeDefs, resolvers } = require('./schemas');
const { start } = require('repl');
const { type } = require('os');
const server = new ApolloServer({
  typeDefs,
  resolvers
});

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// if we're in production, serve client/build as static assets
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/build/index.html'))
})

const startApolloServer = async (typeDefs, resolvers) => {
  await server.start();
  server.applyMiddleware({ app });

  db.once('open', () => {
    app.listen(PORT, () => {
      console.log(`🌍 Now listening on localhost:${PORT}`);
      console.log(`use graphQL at http://localhost:${PORT}${server.graphqlPath}`)
    })
  });
}

startApolloServer(typeDefs, resolvers);