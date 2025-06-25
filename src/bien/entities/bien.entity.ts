import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, OneToMany, JoinColumn } from 'typeorm';
import { Utilisateur } from 'src/users/entities/user.entity';
import { PropertyStatus } from 'src/enums/enums';
import { Location } from 'src/location/entities/location.entity';
import { Paiement } from 'src/paiement/entities/paiement.entity';

@Entity('biens')
export class Bien {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255 })
  adresse: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  ville: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({ type: 'decimal', precision: 8, scale: 2, nullable: true })
  surface: number; // en m²

  @Column({ type: 'jsonb' })
  pieces: {
    id: string; // Identifiant unique de la pièce
    nom: string;
    type: string;
    photos: string[];
    loyerMensuel: number;
    statut: PropertyStatus; // DISPONIBLE/OCCUPÉ/etc.
    description?: string;
  }[] = [];

    @Column({ nullable:false})
  nombredepiece: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  charges: number;

  @Column({ type: 'date', nullable: true })
  disponibleLe: Date;

  @Column({ type: 'uuid' })
  proprietaireId: string;

  @CreateDateColumn()
  creeLe: Date;

  @UpdateDateColumn()
  misAJourLe: Date;

  @ManyToOne(() => Utilisateur, utilisateur => utilisateur.biens)
  @JoinColumn({ name: 'proprietaireId' })
  proprietaire: Utilisateur;

  @OneToMany(() => Location, location => location.bien)
  locations: Location[];

  @OneToMany(() => Paiement, paiement => paiement.bien)
  paiements: Paiement[];
}