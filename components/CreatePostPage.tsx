

import React, { useState, useRef } from 'react';
import { Upload, Wand2, Send, Image as ImageIcon, X } from 'lucide-react';
import { generateCreativeCaptions } from '../services/geminiService';

export const CreatePostPage: React.FC = () => {
  const [caption, setCaption] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setImageFile(file);
      setImagePreview(URL.createObjectURL(file));
    }
  };

  const handleAiEnhance = async () => {
    if (!caption.trim()) return;
    setIsGenerating(true);
    const newCaption = await generateCreativeCaptions(caption);
    setCaption(newCaption);
    setIsGenerating(false);
  };

  const handleSubmit = async () => {
    if (!imageFile || !caption) {
      alert("Please provide both an image and a caption.");
      return;
    }
    
    setIsSubmitting(true);
    
    try {
        // 1. Upload Image
        const formData = new FormData();
        formData.append('file', imageFile);
        
        const uploadRes = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (!uploadRes.ok) throw new Error("Image upload failed");
        
        const { url: imageUrl } = await uploadRes.json();
        
        // 2. Create Post
        const postRes = await fetch('/api/posts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ caption, imageUrl })
        });

        if (!postRes.ok) throw new Error("Failed to create campaign");

        alert("Campaign created successfully!");
        setCaption('');
        setImageFile(null);
        setImagePreview(null);
        
    } catch (e: any) {
        console.error("Submission failed", e);
        alert(`Error: ${e.message || 'Something went wrong'}`);
    } finally {
        setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <header>
        <h2 className="text-2xl font-bold text-slate-800">Create Campaign</h2>
        <p className="text-slate-500">Draft a post to broadcast across all active accounts.</p>
      </header>

      <div className="max-w-2xl mx-auto">
        
        {/* Editor Column */}
        <div className="space-y-6">
          
          {/* Image Upload */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <h3 className="font-semibold text-slate-700 mb-4 flex items-center gap-2">
              <ImageIcon size={18} /> Media
            </h3>
            
            {!imagePreview ? (
              <div 
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-slate-300 rounded-lg p-8 flex flex-col items-center justify-center text-slate-400 hover:border-blue-500 hover:text-blue-500 hover:bg-slate-50 transition-all cursor-pointer h-64"
              >
                <Upload size={32} className="mb-2" />
                <span className="text-sm font-medium">Click to upload image</span>
                <span className="text-xs mt-1">JPG or PNG up to 8MB</span>
              </div>
            ) : (
              <div className="relative rounded-lg overflow-hidden border border-slate-200">
                <img src={imagePreview} alt="Preview" className="w-full h-64 object-cover" />
                <button 
                  onClick={() => { setImageFile(null); setImagePreview(null); }}
                  className="absolute top-2 right-2 p-1 bg-black/50 hover:bg-black/70 text-white rounded-full transition-colors"
                >
                  <X size={16} />
                </button>
              </div>
            )}
            <input 
              type="file" 
              ref={fileInputRef} 
              className="hidden" 
              accept="image/*" 
              onChange={handleImageChange}
            />
          </div>

          {/* Caption Editor */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <div className="flex justify-between items-center mb-4">
              <h3 className="font-semibold text-slate-700">Caption</h3>
              <button 
                onClick={handleAiEnhance}
                disabled={isGenerating || !caption}
                className="text-xs font-medium text-purple-600 hover:text-purple-700 flex items-center gap-1 disabled:opacity-50"
              >
                <Wand2 size={14} />
                {isGenerating ? 'Enhancing...' : 'Enhance with AI'}
              </button>
            </div>
            
            <textarea
              value={caption}
              onChange={(e) => setCaption(e.target.value)}
              placeholder="Enter your caption here... Use {Hello|Hi} for variation."
              className="w-full h-40 p-3 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 resize-none"
            />
            <p className="text-xs text-slate-400 mt-2">
              Tip: Use <code>{`{Option A|Option B}`}</code> to randomize text per account to avoid spam filters.
            </p>
          </div>

          <button
            onClick={handleSubmit}
            disabled={isSubmitting}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-xl shadow-lg shadow-blue-900/20 transition-all flex items-center justify-center gap-2 disabled:opacity-70"
          >
            {isSubmitting ? (
              'Processing...'
            ) : (
              <>
                <Send size={18} /> Launch Campaign
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};