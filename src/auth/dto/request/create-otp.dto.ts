import { IsDate, IsEmail, IsNotEmpty, IsNumber } from "class-validator";


export class CreateOtpDto {

    @IsNotEmpty()
    @IsEmail()
    userEmail: string
    @IsNumber()
    @IsNotEmpty()
    otp: number
    @IsDate()
    @IsNotEmpty()
    created_at: Date
    @IsDate()
    @IsNotEmpty()
    expired_at: Date

}
