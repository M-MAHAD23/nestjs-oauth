import {Model} from "mongoose";
import {InjectModel} from "@nestjs/mongoose";
import {OTP, OTPDocument} from "./model/otp.schema";
import {CreateOtpDto} from "./dto/request/create-otp.dto";
import {VerfiyOtpDto} from "./dto/request/verfiy-otp.dto";

export class OtpRepository{
    constructor(
        @InjectModel(OTP.name) private readonly otpModel: Model<OTPDocument>,
        ) {}
    async create(body:CreateOtpDto){
        return await this.otpModel.create(body)
    }
    async findOne(query: VerfiyOtpDto){
        return this.otpModel.findOne({otp: query.otp, isActive: true, userEmail: query.email})
    }
    async deleteOtp(id:string){
        return this.otpModel.findByIdAndUpdate(id, {isActive: false}, {new: true})
    }
    async countOtp(email:string,timeThreshold:Date){
        return this.otpModel.countDocuments({
            userEmail: email,
            created_at: {$gte: timeThreshold},
            isActive:true
        });
    }
}