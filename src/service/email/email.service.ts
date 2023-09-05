import {Injectable} from '@nestjs/common';
import {ConfigService} from "@nestjs/config";
import {MailerService} from "@nestjs-modules/mailer";
import {UpdateEmailDto} from "./dto/update-email.dto";

@Injectable()
export class EmailService {

    constructor(
        private readonly mailService: MailerService,
        private readonly configService: ConfigService
    ) {
    }

    async sendEmail(subject, fileName, email, replacements , html = null) {
        try {
            let response
            if(replacements.OTP) {
                 response = await this.mailService.sendMail({
                    to: email,
                    from: this.configService.get('MAIL_EMAIL'),
                    subject: subject,
                    template: fileName,
                    context: {
                        name: replacements.name,
                        1: replacements.OTP[0],
                        2: replacements.OTP[1],
                        3: replacements.OTP[2],
                        4: replacements.OTP[3],
                    },
                });
            }
            else{
                response = await this.mailService.sendMail({
                    to: email,
                    from: this.configService.get('MAIL_EMAIL'),
                    subject: subject,
                    template: fileName,
                    context: {
                        name: replacements.name
                    },
                });
            }
// this response is wrapping in user service no need to worry
            return response
        } catch (err) {
            return err
        }

    }


    findAll() {
        return `This action returns all email`;
    }

    findOne(id: number) {
        return `This action returns a #${id} email`;
    }

    update(id: number, updateEmailDto: UpdateEmailDto) {
        return `This action updates a #${id} email`;
    }

    remove(id: number) {
        return `This action removes a #${id} email`;
    }
}
