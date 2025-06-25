import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';
import { Exclude } from 'class-transformer';
import { UserRole } from 'src/enums/enums';
import { Bien } from 'src/bien/entities/bien.entity';
import { Location } from 'src/location/entities/location.entity';

@Entity('utilisateurs')
export class Utilisateur {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 100 })
  nom: string;

  @Column({ type: 'varchar', length: 100 })
  prenom: string;

  @Column({ type: 'varchar', length: 150, unique: true, nullable: true })
  email: string;

  @Column({ type: 'varchar', length: 20, nullable: true })
  telephone: string;

  @Column({ type: 'text', nullable: true })
  adresse: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  @Exclude()
  motDePasse: string;

  @Column({ type: 'varchar', length: 50, unique: true, nullable: true })
  matricule: string; // Pour les locataires

  @Column({ type: 'enum', enum: UserRole, default: UserRole.LOCATAIRE })
  role: UserRole;

  @Column({ type: 'boolean', default: true })
  actif: boolean;

  @CreateDateColumn()
  creeLe: Date;

  @UpdateDateColumn()
  misAJourLe: Date;

  @OneToMany(() => Bien, bien => bien.proprietaire)
  biens: Bien[];

  @OneToMany(() => Location, location => location.locataire)
  locations: Location[];
}
