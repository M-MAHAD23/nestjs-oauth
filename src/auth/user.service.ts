import {
  BadRequestException,
  ConflictException,
  HttpStatus,
  Injectable,
  Logger,
  NotAcceptableException,
  NotFoundException,
  NotImplementedException,
  RequestTimeoutException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { OtpRepository } from './otp.repository';
import { UserRepository } from './user.repository';
import { SignInDto } from './dto/request/sign-in.dto';
import { VerfiyOtpDto } from './dto/request/verfiy-otp.dto';
import { CreateUserDto } from './dto/request/create-user.dto';
import { UpdateUserDto } from './dto/request/update-user.dto';
import { EmailService } from '../service/email/email.service';
import { ApiResponseDto } from '../../core/generic Response/Api-response-dto';
import { ChangePasswordDto, ResetPasswordDto } from './dto/request/reset-password.dto';
import { ResponseUserDto, UpdateProfileResponseUserDto } from './dto/response/response-user.dto';
import { OAuth2Client } from 'google-auth-library';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

@Injectable()
export class UserService {
  private logger = new Logger(UserService.name);
  constructor(
    private readonly userRepository: UserRepository,
    private readonly otpRepository: OtpRepository,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
  ) {}

  // (OTP generator)it ensures the uniqueness according to given secret and windows current time
  generateOTP() {
    const min = 1000; // Minimum 4-digit number (inclusive)
    const max = 9999; // Maximum 4-digit number (inclusive)
    const otp = Math.floor(Math.random() * (max - min + 1)) + min;
    return otp;
  }

  async verifyGoogleToken(token) {
    try {
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: GOOGLE_CLIENT_ID,
      });
      return { payload: ticket.getPayload() };
    } catch (error) {
      // console.log(error);
      this.logger.error(`Invalid Google Token Error:${error}`);
      return { error: 'Invalid user detected. Please try again' };
    }
  }

  async signupGoogle(req: Request) {
    try {
      if (req.body.credential) {
        const verificationResponse = await this.verifyGoogleToken(
          req.body.credential,
        );

        if (verificationResponse.error) {
          throw new BadRequestException(verificationResponse.error);
        }
        const profile = verificationResponse?.payload;
        let accessToken;
        const emailExist = await this.userRepository.findOne(profile?.email);
        if (emailExist) {
          accessToken = this.jwtService.sign(
            { id: emailExist.id },
            { secret: this.configService.get('JWT_SECRET') },
          );
          const response: ApiResponseDto<ResponseUserDto> = {
            statusCode: HttpStatus.OK,
            message: 'Signup successfully',
            data: {
              id: emailExist.id,
              firstName: emailExist.firstName,
              lastName: emailExist.lastName,
              picture: emailExist.picture,
              email: emailExist.email,
              phone: emailExist.phone,
              accessToken: accessToken,
              isActive: emailExist.isActive,
              createdAt: emailExist.createdAt,
              updatedAt: emailExist.updatedAt,
              deletedAt: emailExist.deletedAt,
            },
            error: false,
          };
          return response;
        }
        const userData = {
          firstName: profile?.given_name,
          lastName: profile?.family_name,
          picture: profile?.picture,
          email: profile?.email,
          emailVerified: true,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        const user = await this.userRepository.create(userData);
        if (!user) {
          throw new NotImplementedException(`Cannot create user`);
        }
        accessToken = this.jwtService.sign(
          { id: user.id },
          { secret: this.configService.get('JWT_SECRET') },
        );
        const response: ApiResponseDto<ResponseUserDto> = {
          statusCode: HttpStatus.OK,
          message: 'Signup successfully',
          data: {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            phone: user.phone,
            accessToken: accessToken,
            picture: user.picture,
            isActive: user.isActive,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
            deletedAt: user.deletedAt,
          },
          error: false,
        };
        return response;
      } else {
        throw new NotAcceptableException('Credentials Not provided Correctly');
      }
    } catch (err) {
      this.logger.error(`Registration with Google Failed Error: ${err}`);
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: err.message || 'An error occurred. Registration failed.',
        data: null,
        error: true,
      };
      return response;
    }
  }

  async signup(body: CreateUserDto) {
    try {
      let user;
      //checking if email already exist?

      const emailExist = await this.userRepository.findOne(body.email);
      if (emailExist && emailExist.emailVerified == true) {
        throw new ConflictException('Email Already Exist');
      }
      if (!emailExist) {
        const salt = await bcrypt.genSalt();
        body.password = await bcrypt.hash(body.password, salt);
        user = await this.userRepository.create(body);
      } else {
        const salt = await bcrypt.genSalt();
        body.password = await bcrypt.hash(body.password, salt);
        const { email, ...rembody } = body;
        user = await this.userRepository.findOneAndUpdate(email, rembody);
      }
      if (!user) {
        throw new NotImplementedException('User not created');
      }

      const sendEmail = await this.sendOTP(body.email, 'otp.hbs');
      if (sendEmail.error == true) {
        throw new NotImplementedException('Cannot send OTP');
      } else {
        const response: ApiResponseDto<null> = {
          statusCode: sendEmail.statusCode,
          message: sendEmail.message || '',
          data: null,
          error: false,
        };
        return response;
      }
    } catch (err) {
      this.logger.error(`Signup fail, cannot send OTP Error: ${err}`);
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: err.message || 'An error occurred. Email Sending Fail.',
        data: null,
        error: true,
      };
      return response;
    }
  }

  async verifySignup(query: VerfiyOtpDto) {
    try {
      if (!query.otp && !query.email) {
        throw new BadRequestException('Email or OTP is missing');
      }

      if (await this.verifyOTP(query.otp, query.email)) {
        const userData = await this.userRepository.findOne(query.email);

        if (!userData) {
          throw new NotFoundException('User not found');
        }

        let accessToken = this.jwtService.sign(
          { id: userData.id },
          { secret: this.configService.get('JWT_SECRET') },
        );

        const response: ApiResponseDto<ResponseUserDto> = {
          statusCode: HttpStatus.ACCEPTED,
          message: 'Verification Successful',
          data: {
            id: userData.id,
            firstName: userData.firstName,
            lastName: userData.lastName,
            email: userData.email,
            phone: userData.phone,
            accessToken: accessToken,
            picture: '',
            isActive: userData.isActive,
            createdAt: userData.createdAt,
            updatedAt: userData.updatedAt,
            deletedAt: userData.deletedAt,
          },
          error: false,
        };
        return response;
      } else {
        throw new UnauthorizedException('Verification Failed');
      }
    } catch (err) {
      this.logger.error(`OTP verification Failed Error: ${err}`);
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: err.message || 'An error occurred. Verification failed.',
        data: null,
        error: true,
      };
      return response;
    }
  }

  async sendOTP(email: string, filename: string = 'forgotPassword.hbs') {
    try {
      const user = await this.userRepository.findOne(email);
      if (!user) {
        throw new NotFoundException('User does not exist');
      }
      // setting time 30 min from current time
      const currentTime = new Date();
      const timeThreshold = new Date(currentTime.getTime() - 30 * 60 * 1000); // 30 minutes ago
      //counting if the user attempt three time for otp
      // also checking if the last attempts is 30 min ago than not count it

      const recentOTPAttempts = await this.otpRepository.countOtp(
        email,
        timeThreshold,
      );

      if (recentOTPAttempts >= 3) {
        // calculating display time after he can receive OTP again
        const remainingTime = -Math.ceil(
          currentTime.getMinutes() - timeThreshold.getMinutes(),
        );
        throw new RequestTimeoutException(
          `OTP sending limit reached. Please try again after ${remainingTime} minutes.`,
        );
      }
      const otp = await this.generateOTP();
      const obj = {
        userEmail: email,
        otp: otp,
        created_at: new Date(),
        expired_at: new Date(),
      };
      const expiredAt = new Date(obj.created_at);
      expiredAt.setMinutes(expiredAt.getMinutes() + 2);
      obj.expired_at = expiredAt;
      const sendedOtp = await this.otpRepository.create(obj);
      if (sendedOtp) {
        const OTP = otp.toString();
        const name = user.firstName;
        //here we use Email service to send mail
        const emailResponse = await this.emailService.sendEmail(
          'OTP',
          filename,
          email,
          { OTP, name },
        );
        const response: ApiResponseDto<null> = {
          statusCode: HttpStatus.OK,
          message: emailResponse.message || 'Email sent Successfully',
          data: null,
          error: false,
        };
        return response;
      } else {
        throw new NotImplementedException('Cannot create OTP');
      }
    } catch (err) {
      this.logger.error(`Cannot Send OTP Error:${err}`);
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: err.message || 'Internal Server Error',
        data: null,
        error: true,
      };
      return response;
    }
  }

  async verifyOTP(otp: number, email: string) {
    try {
      const otpObject = await this.otpRepository.findOne({ otp, email });

      if (!otpObject) {
        return false;
      }
      if (otpObject.expired_at > new Date()) {
        const userData = await this.userRepository.findOneAndUpdate(
          otpObject.userEmail,
          { emailVerified: true, isActive: true },
        );

        if (!userData) {
          return false;
        }
        await this.otpRepository.deleteOtp(otpObject.id);

        return true;
      } else {
        return false;
      }
    } catch (err) {
      this.logger.error(`OTP verification fail Error:${err}`);
      return false;
    }
  }

  async resetPassword(body: ResetPasswordDto) {
    try {
      const userExist = await this.userRepository.findOne(body.email);

      if (!userExist) {
        throw new NotFoundException('User not found');
      }

      if (userExist.emailVerified == false) {
        throw new NotAcceptableException('Email not verified');
      }
      if (body.password == body.confirmPassword) {
        const salt = await bcrypt.genSalt();
        body.password = await bcrypt.hash(body.password, salt);
        const userData = await this.userRepository.findOneAndUpdate(
          body.email,
          { password: body.password },
        );

        if (!userData) {
          throw new NotFoundException('User not found');
        }

        const response: ApiResponseDto<null> = {
          statusCode: HttpStatus.OK,
          message: 'Password Changed Successfully',
          data: null,
          error: false,
        };
        return response;
      } else {
        throw new NotAcceptableException('Password does not match');
      }
    } catch (err) {
      this.logger.error(`Could not reset the password Error:${err}`);
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: err.message || 'An error occurred. Verification failed.',
        data: null,
        error: true,
      };
      return response;
    }
  }

  async signin(body: SignInDto) {
    try {
      const user = await this.userRepository.findOne(body.email);
      if (!user) {
        throw new NotFoundException(`User does not exist`);
      }

      if (user.emailVerified == false) {
        throw new NotAcceptableException(`Email not verified`);
      }
      // limiting user to only three attempts of wrong password
      const currentTime = new Date();
      if (
        user.loginAttempts >= 3 &&
        currentTime.getTime() - user.attemptTime.getTime() < 30 * 60 * 1000
      ) {
        throw new RequestTimeoutException(`Please wait before next attempt`);
      } else if (
        user.loginAttempts >= 3 &&
        currentTime.getTime() - user.attemptTime.getTime() > 30 * 60 * 1000
      ) {
        user.loginAttempts = 0;
        user.attemptTime = null;

        await user.save();
      }
      const validation = await bcrypt.compare(body.password, user.password);
      if (validation) {
        // if password is valid then attempts will be 0
        user.loginAttempts = 0;

        user.attemptTime = null;

        user.save();
        let accessToken;
        if (body.rememberMe) {
          accessToken = this.jwtService.sign(
            { id: user.id },
            {
              secret: this.configService.get('JWT_SECRET'),
              expiresIn: '72h',
            },
          );
        }
        accessToken = this.jwtService.sign(
          { id: user.id },
          { secret: this.configService.get('JWT_SECRET') },
        );

        const response: ApiResponseDto<ResponseUserDto> = {
          statusCode: HttpStatus.OK,
          message: 'Signin Successfully',
          data: {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            phone: user.phone,
            accessToken: accessToken,
            picture: '',
            isActive: user.isActive,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
            deletedAt: user.deletedAt,
          },
          error: false,
        };
        return response;
      } else {
        user.loginAttempts += 1;
        user.attemptTime = new Date();
        await user.save();

        throw new BadRequestException('Incorrect Email or Password');
      }
    } catch (err) {
      this.logger.error(`Login Fail due to  Error:${err}`);
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: err.message || 'Internal Server Error',
        data: null,
        error: true,
      };
      return response;
    }
  }

  // Check before creating the contact if user exists on not for contact API
  async findOne(id: string): Promise<boolean> {
    try {
      const user = await this.userRepository.findById(id);
      if (user) {
        return true;
      }
      return false;
    } catch (error) {
      this.logger.error(`Contact creation failed due to  Error:${error}`);
      return false;
    }
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }

  async changePassword(userId: string, changePasswordDto: ChangePasswordDto) {
    try {
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundException('Cannot Find User!');
      }
      const salt = await bcrypt.genSalt();
      if (user.password == null) {
        const userPassword = await bcrypt.hash(
          changePasswordDto.newPassword,
          salt,
        );
        const updateUser = await this.userRepository.findOneAndUpdate(
          user.email,
          { password: userPassword, updatedAt: new Date().toISOString() },
        );
        if (!updateUser) {
          throw new NotImplementedException('Cannot Change Password');
        }
      } else if (user.password) {
        const comparePassword = await bcrypt.compare(
          changePasswordDto.prevPassword,
          user.password,
        );
        if (comparePassword) {
          const userPassword = await bcrypt.hash(
            changePasswordDto.newPassword,
            salt,
          );
          const updateUser = await this.userRepository.findOneAndUpdate(
            user.email,
            { password: userPassword, updatedAt: new Date().toISOString() },
          );
          if (!updateUser) {
            throw new NotImplementedException('Cannot Change Password');
          }
        } else {
          throw new NotImplementedException('Incorrect Password');
        }
      }
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.OK,
        message: 'Password change successfully',
        data: null,
        error: false,
      };
      return response;
    } catch (error) {
      this.logger.error(`Cannot change Password Error:${error}`);
      throw error;
    }
  }

  async checkAccountType(userId: string) {
    try {
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new NotFoundException('User Not Found');
      }
      if (user.password == null && user.emailVerified == true) {
        const response: ApiResponseDto<object> = {
          statusCode: HttpStatus.OK,
          message: 'Record found',
          data: {
            isGoogle: true,
          },
          error: false,
        };
        return response;
      }
      if (user.password && user.emailVerified == true) {
        const response: ApiResponseDto<object> = {
          statusCode: HttpStatus.OK,
          message: 'Record found',
          data: {
            isGoogle: false,
          },
          error: false,
        };
        return response;
      }
    } catch (error) {
      this.logger.error(`Cannot check Account Type Error:${error}`);
      throw error;
    }
  }
  async updateProfile(
    loggedInUserId: string,
    updateUserDto: UpdateUserDto,
  ): Promise<ApiResponseDto<UpdateProfileResponseUserDto>> {
    try {
      const user = await this.userRepository.updateProfile(
        loggedInUserId,
        updateUserDto,
      );
      if (!user)
        throw new NotImplementedException(
          `Could not update the Document with _id: #${loggedInUserId}`,
        );

      const returnUser = {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        picture: user.picture,
        phone: user.phone,
      };

      const response: ApiResponseDto<UpdateProfileResponseUserDto> = {
        statusCode: HttpStatus.OK,
        message: 'Document, Updated Successfully',
        data: returnUser,
        error: false,
      };
      return response;
    } catch (error) {
      this.logger.error(
        `Cannot Update Content-Item in Library, Error:${error}`,
      );
      throw error;
    }
  }

  async delete(loggedInUserId: string): Promise<ApiResponseDto<null>> {
    try {
      const user = await this.userRepository.delete(loggedInUserId);
      if (!user)
        throw new NotImplementedException(
          `Could not delete the Document with _id: #${loggedInUserId}`,
        );

      // Return std response
      const response: ApiResponseDto<null> = {
        statusCode: HttpStatus.OK,
        message: `User with _id: #${loggedInUserId}, Deleted Successfully`,
        data: null,
        error: false,
      };
      return response;
    } catch (error) {
      this.logger.error(`Cannot delete, Error:${error}`);
      throw error;
    }
  }
}
