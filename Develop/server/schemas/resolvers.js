const { User } = require('../models');
const { AuthenticationError } = require('apollo-server-express');
const { signToken } = require('../utils/auth');
const { sign } = require('jsonwebtoken');

const resolvers = {
    Query: {
        users: async () => {
            return await User.find({}).populate('savedBooks');
        },
        user: async (parent, { thoughtId }) => {
            return await User.findOne({ _id: thoughtId }).populate('savedBooks');
        }
    },

    Mutation: {
        addUser: async (parent, { username, email, password }) => {
            const user = await User.create({ username, email, password });
            const token = signToken(user);
            return { token, user }
        },
        login: async (parent, { email, password }) => {
            const user = await User.findOne({ email });
            if (!user) {
                throw new AuthenticationError('no user with that email')
            }
            const correctPw = await user.isCorrectPassword(password);
            if (!correctPw) {
                throw new AuthenticationError('incorrect credentials');
            }
            const token = signToken(user);
            return { token, user };
        },
        findUser: async (parent, { user = null, params }, context) => {
            if (context.user) {
                const foundUser = await User.findOne({
                    $or: [{ _id: user ? user._id : params.id }, { username: params.username }],
                });
                return foundUser;
            }
            throw new AuthenticationError('You need to be logged in!');
        },
        addBook: async (parent, { userId, body }, context) => {
            if (context.user) {
                return User.findOneAndUpdate(
                    { _id: userId },
                    {
                        $addToSet: { savedBooks: { body } }
                    },
                    {
                        new: true,
                        runValidators: true,
                    })
            }
            throw new AuthenticationError('You need to be logged in!')
            
        },
        deleteBook: async(parent, { userId, bookId }, context) => {
            if (context.user) {
                return User.findOneAndUpdate(
                    { _id: userId },
                    { $pull: { savedBooks: { bookId: bookId } }},
                    { new: true }
                )
            }
            throw new AuthenticationError('You need to be logged in!');
        }
    }
};

module.exports = resolvers;