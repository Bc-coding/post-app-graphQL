import { Context } from "..";

export const Query = {
  me: async (_: any, __: any, { prisma, userInfo }: Context) => {
    if (!userInfo) return null;
    return prisma.user.findUnique({
      where: {
        id: userInfo.userId,
      },
    });
  },
  profile: async (
    _: any,
    { userId }: { userId: string },
    { prisma }: Context
  ) => {
    return prisma.profile.findUnique({
      where: {
        userId: Number(userId),
      },
    });
  },
  posts: async (_: any, __: any, { prisma }: Context) => {
    const posts = prisma.post.findMany({
      where: {
        published: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });
    return posts;
  },
};
