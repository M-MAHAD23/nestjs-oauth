import {IsEmail, IsNotEmpty, IsNumber} from "class-validator";

export class VerfiyOtpDto {
    @IsNotEmpty()
    @IsEmail()
    email: string
    @IsNotEmpty()
    @IsNumber()
    otp: number

}
