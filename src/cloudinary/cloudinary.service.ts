import { Injectable } from '@nestjs/common';
import { v2 as cloudinary } from 'cloudinary';
import { ConfigService } from '@nestjs/config';


@Injectable()
export class CloudinaryService {
  constructor(private configService: ConfigService) {
    cloudinary.config({
      cloud_name: this.configService.get<string>('CLOUDINARY_CLOUD_NAME'),
      api_key: this.configService.get<string>('CLOUDINARY_API_KEY'),
      api_secret: this.configService.get<string>('CLOUDINARY_API_SECRET'),
    });
  }

  async uploadImage(file: Express.Multer.File, folder: string = 'biens'): Promise<string> {
    try {
      const result = await cloudinary.uploader.upload(file.buffer.toString('base64'), {
        resource_type: 'image',
        folder: folder,
        public_id: `${folder}_${Date.now()}`,
        transformation: [
          { width: 800, height: 600, crop: 'limit' },
          { quality: 'auto' },
          { format: 'auto' }
        ]
      });
      
      return result.secure_url;
    } catch (error) {
      throw new Error(`Erreur lors de l'upload vers Cloudinary: ${error.message}`);
    }
  }

  async uploadMultipleImages(files: Express.Multer.File[], folder: string = 'biens'): Promise<string[]> {
    const uploadPromises = files.map(file => this.uploadImage(file, folder));
    return Promise.all(uploadPromises);
  }

  async deleteImage(publicId: string): Promise<void> {
    try {
      await cloudinary.uploader.destroy(publicId);
    } catch (error) {
      console.error(`Erreur lors de la suppression de l'image: ${error.message}`);
    }
  }

  // Extraire le public_id d'une URL Cloudinary
  extractPublicId(url: string): string {
    const parts = url.split('/');
    const filename = parts[parts.length - 1];
    return filename.split('.')[0];
  }
}