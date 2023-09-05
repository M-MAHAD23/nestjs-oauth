import { HttpStatus } from '@nestjs/common';

export interface ApiResponseDto<T> {
    statusCode: HttpStatus;
    message: string;
    data: T;
    error: boolean;
}
