const { gql } = require('apollo-server-express');

const typeDefs = gql`
    type User {
        _id: ID!
        username: String!
        email: String!
        password: String!
        savedBooks: [bookSchema]
    }
    
    type Query {
        users: [User]
    }
`;

module.exports = typeDefs;