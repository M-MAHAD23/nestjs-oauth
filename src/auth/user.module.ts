import {Module} from '@nestjs/common';
import {UserService} from './user.service';
import {UserController} from './user.controller';
import {MongooseModule} from "@nestjs/mongoose";
import {User, UserSchema} from "./model/user.schema";
import {JwtModule} from "@nestjs/jwt";
import {OTP, OTPSchema} from "./model/otp.schema";
import {OtpRepository} from "./otp.repository";
import {UserRepository} from "./user.repository";
import {EmailModule} from "../service/email/email.module";

@Module({
    imports: [
        MongooseModule.forFeature([
            {name: User.name, schema: UserSchema},
            {name: OTP.name, schema: OTPSchema}
        ]),
        JwtModule,
        EmailModule
    ],
    controllers: [UserController],

    exports: [UserService],

    providers: [UserService,UserRepository,OtpRepository]

})
export class UserModule {
}
