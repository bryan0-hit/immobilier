import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Location } from 'src/location/entities/location.entity';
import { Bien } from 'src/bien/entities/bien.entity';
import { PaymentStatus, PaymentMethod } from 'src/enums/enums';


@Entity('paiements')
export class Paiement {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  locationId: string;

  @Column({ type: 'uuid' })
  bienId: string;

  @Column({ type: 'decimal', precision: 10, scale: 2 })
  montant: number;

  @Column({ type: 'date' })
  echeance: Date;

  @Column({ type: 'date', nullable: true })
  payeLe: Date;

  @Column({ type: 'enum', enum: PaymentStatus, default: PaymentStatus.EN_ATTENTE })
  statut: PaymentStatus;

  @Column({ type: 'enum', enum: PaymentMethod, nullable: true })
  methodePaiement: PaymentMethod;

  @Column({ type: 'varchar', length: 100, nullable: true })
  reference: string;

  @Column({ type: 'text', nullable: true })
  notes: string;

  @Column({ type: 'integer' })
  mois: number;

  @Column({ type: 'integer' })
  annee: number;

  @CreateDateColumn()
  creeLe: Date;

  @UpdateDateColumn()
  misAJourLe: Date;

  @ManyToOne(() => Location, location => location.paiements)
  @JoinColumn({ name: 'locationId' })
  location: Location;

  @ManyToOne(() => Bien, bien => bien.paiements)
  @JoinColumn({ name: 'bienId' })
  bien: Bien;
}
