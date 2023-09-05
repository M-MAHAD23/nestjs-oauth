import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";

@Schema()
export class User {

  @Prop()
  firstName: string;

  @Prop()
  lastName: string;

  @Prop({ unique: true })
  email: string;

  @Prop({ default: null })
  phone: string;

  @Prop({ default: null })
  picture: string;

  @Prop({ default: null })
  password: string;

  @Prop({ default: false })
  emailVerified: boolean;

  @Prop({ default: true })
  isActive: boolean;

  @Prop()
  createdAt: string;

  @Prop()
  updatedAt: string;

  @Prop({ default: null })
  deletedAt: string;

  // SignIn
  @Prop({ default: null })
  loginAttempts: number;

  @Prop({ default: null })
  attemptTime: Date;

}

export type UserDocument = User & Document;

export const UserSchema = SchemaFactory.createForClass(User);