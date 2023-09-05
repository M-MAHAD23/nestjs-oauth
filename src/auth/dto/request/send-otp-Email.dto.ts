import {IsEmail, IsNotEmpty} from "class-validator";

export class SendOtpEmailDto {

    @IsNotEmpty()
    @IsEmail()
    email: string
}
