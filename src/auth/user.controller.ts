import {
  Body,
  Controller,
  Delete,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {Request, Response} from 'express';
import {UserService} from './user.service';
import {SignInDto} from './dto/request/sign-in.dto';
import {VerfiyOtpDto} from './dto/request/verfiy-otp.dto';
import {CreateUserDto} from './dto/request/create-user.dto';
import {UpdateUserDto} from './dto/request/update-user.dto';
import {ResetPasswordDto} from './dto/request/reset-password.dto';
import {ApiResponseDto} from 'core/generic Response/Api-response-dto';
import {AuthGuard, RequestWithUser} from '../../core/guards/auth-guard';
import {UpdateProfileResponseUserDto} from './dto/response/response-user.dto';

@Controller('/user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @UseGuards(AuthGuard)
  @Patch('/change-password')
  async changePassword(@Req() req: RequestWithUser, @Body() body: any) {
    return this.userService.changePassword(req.user.id, body);
  }

  @Post('/signup-with-google')
  async signupGoogle(@Req() req: Request, @Res() res: Response) {
    const user = await this.userService.signupGoogle(req);
    if (user.error) {
      throw new HttpException(
        {
          statusCode: HttpStatus.BAD_REQUEST,
          message: user.message,
          data: null,
          error: true,
        },
        HttpStatus.BAD_REQUEST,
      );
    }
    res.json(user);
  }

  @Post('/signup')
  async signup(@Body() body: CreateUserDto) {
    return this.userService.signup(body);
  }

  @Get('/verify-signup')
  async verifySignup(
    @Query('otp') otp: number,
    @Query('email') email: string,
    @Res() res: Response,
  ) {
    const verify = await this.userService.verifySignup({ otp, email });
    res.json(verify);
  }

  @Post('/verify-otp')
  async verifyOtp(@Body() body: VerfiyOtpDto) {
    return this.userService.verifyOTP(body.otp, body.email);
  }

  @Post('/reset-password')
  async resetPassword(@Body() body: ResetPasswordDto) {
    return this.userService.resetPassword(body);
  }

  @Get('/get-otp')
  async getOtp(@Query('email') email: string) {
    return await this.userService.sendOTP(email);
  }

  @Post('/sign-in')
  async signin(@Body() body: SignInDto, @Res() res: Response) {
    const response = await this.userService.signin(body);
    res.json(response);
  }
  
  @UseGuards(AuthGuard)
  @Get('/check-account-type')
  async checkAccountType(@Req() req: RequestWithUser) {
    return this.userService.checkAccountType(req.user.id);
  }

  @UseGuards(AuthGuard)
  @Get('find-user:id')
  findOne(@Req() req: RequestWithUser, @Param('id') id: string) {
    const loggedInUserId = req?.user?.id;
    return this.userService.findOne(loggedInUserId);
  }

  @UseGuards(AuthGuard)
  @Patch('update-profile')
  updateProfile(
    @Req() req: RequestWithUser,
    @Body() updateUserDto: UpdateUserDto,
  ): Promise<ApiResponseDto<UpdateProfileResponseUserDto>> {
    const loggedInUserId = req?.user?.id;
    return this.userService.updateProfile(loggedInUserId, updateUserDto);
  }

  @UseGuards(AuthGuard)
  @Delete('delete-profile')
  delete(@Req() req: RequestWithUser): Promise<ApiResponseDto<null>> {
    const loggedInUserId = req?.user?.id;
    return this.userService.delete(loggedInUserId);
  }
}
