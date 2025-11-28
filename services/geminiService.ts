import { GoogleGenAI } from "@google/genai";

export const generateCreativeCaptions = async (baseCaption: string): Promise<string> => {
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: `Reword the following social media caption to be more engaging. 
      Keep the core message but make it sound professional yet exciting. 
      Add appropriate emojis.
      
      Original Caption: "${baseCaption}"`,
    });

    return response.text?.trim() ?? baseCaption;
  } catch (error) {
    console.error("Gemini API Error:", error);
    return baseCaption; // Fallback to original
  }
};