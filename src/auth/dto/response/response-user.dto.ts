export class ResponseUserDto {
    id:string
    firstName: string
    lastName: string
    email: string
    picture: string
    phone:string
    accessToken: string
    isActive:boolean
    createdAt:string
    updatedAt:string
    deletedAt:string
}


export class UpdateProfileResponseUserDto{
    id:string
    firstName: string
    lastName: string
    email: string
    picture: string
    phone:string
}