import {Module} from '@nestjs/common';
import {EmailService} from './email.service';
import {MailerModule} from "@nestjs-modules/mailer";


@Module({
    imports: [MailerModule],
    providers: [EmailService],
    exports: [EmailService]
})
export class EmailModule {
}
