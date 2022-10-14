import { Post, Prisma } from "@prisma/client";
import { Context } from "../../index";
import validator from "validator";
import bcrypt from "bcryptjs";
import JWT from "jsonwebtoken";

interface SignupArgs {
  credentials: {
    email: string;
    password: string;
  };
  name: string;
  bio: string;
}

interface SigninArgs {
  credentials: {
    email: string;
    password: string;
  };
}

interface UserPayload {
  userErrors: {
    message: string;
  }[];
  token: string | null;
}

export const authResolvers = {
  signup: async (
    _: any,
    { credentials, name, bio }: SignupArgs,

    { prisma }: Context
  ): Promise<UserPayload> => {
    const { email, password } = credentials;

    const isEmail = validator.isEmail(email);

    if (!isEmail) {
      return {
        userErrors: [
          {
            message: "invalid email",
          },
        ],
        token: null,
      };
    }

    const isValidPassword = validator.isLength(password, {
      min: 8,
    });

    if (!isValidPassword) {
      return {
        userErrors: [
          {
            message:
              "The length of password needs to be greater than 8 characters",
          },
        ],
        token: null,
      };
    }

    if (!name || !bio) {
      return {
        userErrors: [
          {
            message: "inlavid input",
          },
        ],
        token: null,
      };
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword,
      },
    });

    await prisma.profile.create({
      data: {
        bio,
        userId: user.id,
      },
    });

    const token = await JWT.sign(
      {
        userId: user.id,
        email: user.email,
      },
      process.env.JWT_SINGANITURE!,
      { expiresIn: 36000000 }
    );

    return {
      userErrors: [],
      token,
    };
  },

  signin: async (
    _: any,
    { credentials }: SigninArgs,
    { prisma }: Context
  ): Promise<UserPayload> => {
    const { email, password } = credentials;

    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return {
        userErrors: [
          {
            message: "Invalid credentials",
          },
        ],
        token: null,
      };
    }

    const isMatched = await bcrypt.compare(password, user.password);

    if (!isMatched) {
      return {
        userErrors: [
          {
            message: "Invalid credentials",
          },
        ],
        token: null,
      };
    }

    return {
      userErrors: [],
      token: JWT.sign(
        {
          userId: user.id,
        },
        process.env.JWT_SINGANITURE!,
        {
          expiresIn: 3600000,
        }
      ),
    };
  },
};
