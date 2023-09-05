import {Prop, Schema, SchemaFactory} from "@nestjs/mongoose";
import {Document} from "mongoose";

export type OTPDocument = OTP & Document;

@Schema()
export class OTP {

    @Prop({required: true})
    userEmail: string
    @Prop({required: true})
    otp: number
    @Prop()
    created_at: Date
    @Prop()
    expired_at: Date
    @Prop({default: true})
    isActive: boolean

}

export const OTPSchema = SchemaFactory.createForClass(OTP);
