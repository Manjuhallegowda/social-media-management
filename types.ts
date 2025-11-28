export enum AccountStatus {
  ACTIVE = 'active',
  DISCONNECTED = 'disconnected',
  ERROR = 'error'
}

export enum PostStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed'
}

export interface SocialAccount {
  id: string; // Internal UUID
  owner_name: string;
  fb_page_name: string;
  ig_username: string;
  status: AccountStatus;
  last_updated: string;
}

export interface PostCampaign {
  id: string;
  image_url: string;
  base_caption: string;
  status: PostStatus;
  total_accounts: number;
  success_count: number;
  failure_count: number;
  created_at: string;
}

export interface LogEntry {
  id: string;
  post_id: string;
  account_name: string;
  status: 'success' | 'failed';
  message: string; // Error message or Meta Post ID
  timestamp: string;
}

// Meta API Types (Subset)
export interface MetaMeAccountsResponse {
  data: Array<{
    access_token: string;
    category: string;
    name: string;
    id: string;
    instagram_business_account?: {
      id: string;
    };
  }>;
}