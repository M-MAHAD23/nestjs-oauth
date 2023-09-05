import mongoose, { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './model/user.schema';
import { CreateUserDto } from './dto/request/create-user.dto';
import { UpdateUserDto } from './dto/request/update-user.dto';

export class UserRepository {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) { }


  async create(user: CreateUserDto) {
    return this.userModel.create(user);
  }
  async findOne(email: string) {
    return this.userModel.findOne({ 
      email: email,
      isActive: true,
     });
  }
  async findById(id: string) {
    return this.userModel.findById(id);
  }
  async findOneAndUpdate(email: string, body: UpdateUserDto) {
    return this.userModel.findOneAndUpdate({ email: email }, body,
      { new: true })
  }


  async updateProfile(loggedInUserId: string, updateUserDto: UpdateUserDto): Promise<UserDocument> {
    const _id = new mongoose.Types.ObjectId(loggedInUserId);    
    const contentItem = await this.userModel.findByIdAndUpdate(_id, updateUserDto, { new: true });
    return contentItem;
  }

  async delete(loggedInUserId: string): Promise<UserDocument> {
    const _id = new mongoose.Types.ObjectId(loggedInUserId);
    const user = await this.userModel.findById(_id);
    user.isActive = false;
    user.deletedAt = new Date().toISOString();
    await user.save();
    return user;
  }
}

