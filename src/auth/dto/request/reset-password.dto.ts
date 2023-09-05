import {IsEmail, IsNotEmpty, IsNumber, IsOptional, IsString} from "class-validator";

export class ResetPasswordDto {
    @IsEmail()
    @IsNotEmpty()
    email: string
    @IsString()
    @IsNotEmpty()
    password: string
    @IsString()
    @IsNotEmpty()
    confirmPassword: string

}

export class ChangePasswordDto{
    @IsString()
    @IsNotEmpty()
    newPassword:string
    @IsString()
    @IsOptional()
    prevPassword:string
}