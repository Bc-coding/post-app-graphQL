import { ApolloServer, gql } from "apollo-server";
import { typeDefs } from "./schema";
import { Query, Mutation, Profile, Post, User } from "./resolvers/index";
import { PrismaClient, Prisma } from "@prisma/client";
import { getUserFromToken } from "./utils/getUserFromToken";

const prisma = new PrismaClient();

export interface Context {
  prisma: PrismaClient<
    Prisma.PrismaClientOptions,
    never,
    Prisma.RejectOnNotFound | Prisma.RejectPerOperation | undefined
  >;
  userInfo: {
    userId: number;
  } | null;
}

const server = new ApolloServer({
  typeDefs,
  resolvers: {
    Query,
    Mutation,
    Profile,
    Post,
    User,
  },
  context: async ({ req, res }: any): Promise<Context> => {
    //console.log(req.headers.authorization);
    const userInfo = await getUserFromToken(req.headers.authorization);

    // console.log(userInfo);

    return {
      prisma,
      userInfo,
    };
  },
});

server.listen().then(({ url }) => {
  console.log(`Server ready on ${url}`);
});
