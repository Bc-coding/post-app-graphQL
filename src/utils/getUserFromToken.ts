import JWT from "jsonwebtoken";

export const getUserFromToken = (token: string) => {
  try {
    return JWT.verify(token, process.env.JWT_SINGANITURE!) as {
      userId: number;
    };
  } catch (error) {
    // console.log(error);
    return null;
  }
};
