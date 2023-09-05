import {IsEmail, IsNotEmpty, IsOptional, IsString} from "class-validator";

export class SignInDto{
    @IsEmail()
    @IsNotEmpty()
    email:string
    @IsString()
    @IsNotEmpty()
    password:string
    @IsOptional()
    rememberMe:boolean
}